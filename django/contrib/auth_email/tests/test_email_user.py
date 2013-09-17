# -*- encoding: utf-8 -*-
from __future__ import unicode_literals

from django.utils.encoding import force_text
from django.utils.translation import ugettext as _

from django.db import models
from django.db.models.manager import ensure_default_manager

from django.forms.fields import Field

from django.contrib.auth import get_user_model
from django.contrib.auth.models import PermissionsMixin, Group, Permission

from django.contrib.auth_email.models import User
from django.contrib.auth_email.forms import UserCreationForm, UserChangeForm

from django.test import TestCase
from django.test.utils import override_settings

class ModelTestCase(TestCase):
    """
    Clone of contrib.auth's BasicTestCase, to ensure
    that all functionality works correctly with the new
    User model from auth_email.  Unesseccary tests (AnonymousUser, no email,
    various createsuperuser tests) have been removed.
    """

    User = None

    def _pre_setup(self):
        # setup the email user as the current AUTH_USER_MODEL, and cache it
        self.User = get_user_model()

        #Ensure that the correct manager is being used
        setattr(self.User, 'objects', self.User._default_manager)
        ensure_default_manager(self.User)

        # At this point, temporarily remove the groups and user_permissions M2M
        # fields from the User class, so they don't clash with the related_name
        # that sets.
        self._old_u_local_m2m = self.User._meta.local_many_to_many
        groups = models.ManyToManyField(Group, blank=True)
        groups.contribute_to_class(PermissionsMixin, "groups")
        user_permissions = models.ManyToManyField(Permission, blank=True)
        user_permissions.contribute_to_class(PermissionsMixin, "user_permissions")
        self.User._meta.local_many_to_many = [groups, user_permissions]

        super(ModelTestCase, self)._pre_setup()

    def _post_teardown(self):
        super(ModelTestCase, self)._post_teardown()

        # Restore user m2m field
        self.User._meta.local_many_to_many = self._old_u_local_m2m

    def test_user(self):
        "Check that users can be created and can set their password"

        u = self.User.objects.create_user('test@example.com', 'testpw')
        self.assertTrue(u.has_usable_password())
        self.assertFalse(u.check_password('bad'))
        self.assertTrue(u.check_password('testpw'))

        # Check we can manually set an unusable password
        u.set_unusable_password()
        u.save()
        self.assertFalse(u.check_password('testpw'))
        self.assertFalse(u.has_usable_password())
        u.set_password('testpw')
        self.assertTrue(u.check_password('testpw'))
        u.set_password(None)
        self.assertFalse(u.has_usable_password())

        # Check authentication/permissions
        self.assertTrue(u.is_authenticated())
        self.assertFalse(u.is_staff)
        self.assertTrue(u.is_active)
        self.assertFalse(u.is_superuser)

        # Check API-based user creation with no password
        u2 = get_user_model().objects.create_user('test2@example.com')
        self.assertFalse(u2.has_usable_password())

    def test_superuser(self):
        "Check the creation and properties of a superuser"
        superuser = self.User.objects.create_superuser('super@example.com', 'super')
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_active)
        self.assertTrue(superuser.is_staff)

    def test_get_user_model(self):
        "The current user model can be retrieved"
        self.assertEqual(self.User, User)

@override_settings(USE_TZ=False, PASSWORD_HASHERS=('django.contrib.auth.hashers.SHA1PasswordHasher',))
class UserCreationFormTest(TestCase):

    fixtures = ['authtestcase.json']

    def test_user_already_exists(self):
        data = {
            'email': 'testclient@example.com',
            'password1': 'test123',
            'password2': 'test123',
            }
        form = UserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form["email"].errors,
                         [force_text(form.error_messages['duplicate_email'])])

    def test_password_verification(self):
        # The verification password is incorrect.
        data = {
            'email': 'jsmith@example.com',
            'password1': 'test123',
            'password2': 'test',
            }
        form = UserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form["password2"].errors,
                         [force_text(form.error_messages['password_mismatch'])])

    def test_both_passwords(self):
        # One (or both) passwords weren't given
        data = {'email': 'jsmith@example.com'}
        form = UserCreationForm(data)
        required_error = [force_text(Field.default_error_messages['required'])]
        self.assertFalse(form.is_valid())
        self.assertEqual(form['password1'].errors, required_error)
        self.assertEqual(form['password2'].errors, required_error)

        data['password2'] = 'test123'
        form = UserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form['password1'].errors, required_error)
        self.assertEqual(form['password2'].errors, [])

    def test_success(self):
        # The success case.
        data = {
            'email': 'jsmith@example.com',
            'password1': 'test123',
            'password2': 'test123',
            }
        form = UserCreationForm(data)
        self.assertTrue(form.is_valid())
        u = form.save()
        self.assertEqual(repr(u), '<User: jsmith@example.com>')

@override_settings(USE_TZ=False, PASSWORD_HASHERS=('django.contrib.auth.hashers.SHA1PasswordHasher',))
class UserChangeFormTest(TestCase):

    fixtures = ['authtestcase.json']
    User = None

    def _pre_setup(self):
        # setup the email user as the current AUTH_USER_MODEL, and cache it
        self.User = get_user_model()

        #Ensure that the correct manager is being used
        setattr(self.User, 'objects', self.User._default_manager)
        ensure_default_manager(self.User)

        super(UserChangeFormTest, self)._pre_setup()

    def test_bug_14242(self):
        # A regression test, introduce by adding an optimization for the
        # UserChangeForm.

        class MyUserForm(UserChangeForm):
            def __init__(self, *args, **kwargs):
                super(MyUserForm, self).__init__(*args, **kwargs)
                self.fields['groups'].help_text = 'These groups give users different permissions'

            class Meta(UserChangeForm.Meta):
                fields = ('groups',)

        # Just check we can create it
        form = MyUserForm({})

    def test_unusable_password(self):
        user = self.User.objects.get(email='empty_password@example.com')
        user.set_unusable_password()
        user.save()
        form = UserChangeForm(instance=user)
        self.assertIn(_("No password set."), form.as_table())

    def test_bug_17944_empty_password(self):
        user = self.User.objects.get(email='empty_password@example.com')
        form = UserChangeForm(instance=user)
        self.assertIn(_("No password set."), form.as_table())

    def test_bug_17944_unmanageable_password(self):
        user = self.User.objects.get(email='unmanageable_password@example.com')
        form = UserChangeForm(instance=user)
        self.assertIn(_("Invalid password format or unknown hashing algorithm."),
            form.as_table())

    def test_bug_17944_unknown_password_algorithm(self):
        user = self.User.objects.get(email='unknown_password@example.com')
        form = UserChangeForm(instance=user)
        self.assertIn(_("Invalid password format or unknown hashing algorithm."),
            form.as_table())

    def test_bug_19133(self):
        "The change form does not return the password value"
        # Use the form to construct the POST data
        user = self.User.objects.get(email='testclient@example.com')
        form_for_data = UserChangeForm(instance=user)
        post_data = form_for_data.initial

        # The password field should be readonly, so anything
        # posted here should be ignored; the form will be
        # valid, and give back the 'initial' value for the
        # password field.
        post_data['password'] = 'new password'
        form = UserChangeForm(instance=user, data=post_data)

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['password'], 'sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161')

    def test_bug_19349_bound_password_field(self):
        user = self.User.objects.get(email='testclient@example.com')
        form = UserChangeForm(data={}, instance=user)
        # When rendering the bound password field,
        # ReadOnlyPasswordHashWidget needs the initial
        # value to render correctly
        self.assertEqual(form.initial['password'], form['password'].value())