from __future__ import annotations

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import BooleanField, PasswordField, SelectField, StringField, SubmitField, TextAreaField, IntegerField, HiddenField
from wtforms.fields import DateField
from wtforms.validators import Email, EqualTo, InputRequired, Length, Optional, ValidationError, Regexp

from .models import EquipmentStatus, MaintenanceStatus, RequestType, UserRole, SupportCategory


def _validate_strong_password(form, field) -> None:
    value = field.data or ""
    if len(value) < 12:
        raise ValidationError("Password must be at least 12 characters long.")
    if not any(ch.islower() for ch in value):
        raise ValidationError("Include at least one lowercase letter.")
    if not any(ch.isupper() for ch in value):
        raise ValidationError("Include at least one uppercase letter.")
    if not any(ch.isdigit() for ch in value):
        raise ValidationError("Include at least one number.")
    if not any(ch in "!@#$%^&*()_-+=[]{}|;:'\",.<>?/`~" for ch in value):
        raise ValidationError("Include at least one symbol.")


class LoginForm(FlaskForm):
    organization_slug = StringField(
        "Organization Slug",
        validators=[InputRequired(message="Organization is required"), Length(max=128)],
    )
    email = StringField(
        "Email",
        validators=[InputRequired(message="Email is required"), Email(), Length(max=255)],
    )
    password = PasswordField(
        "Password",
        validators=[InputRequired(message="Password is required"), Length(min=8, max=128)],
    )
    remember_me = BooleanField("Remember this device")
    submit = SubmitField("Sign In")


class RegisterUserForm(FlaskForm):
    name = StringField(
        "Full Name",
        validators=[InputRequired(message="Name is required"), Length(max=255)],
    )
    email = StringField(
        "Email",
        validators=[InputRequired(message="Email is required"), Email(), Length(max=255)],
    )
    password = PasswordField(
        "Password",
        validators=[InputRequired(), Length(min=12, max=128), _validate_strong_password],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[InputRequired(), EqualTo("password", message="Passwords must match")],
    )
    role = SelectField(
        "Role",
        choices=[(UserRole.ADMIN.value, "Organization Admin"), (UserRole.USER.value, "Normal User")],
        validators=[InputRequired()],
    )
    submit = SubmitField("Create User")


class BulkUserUploadForm(FlaskForm):
    file = FileField(
        "User CSV",
        validators=[
            FileRequired(message="CSV file is required"),
            FileAllowed(["csv"], "Only CSV files are allowed."),
        ],
    )
    submit = SubmitField("Upload CSV")


class OrganizationSignupForm(FlaskForm):
    organization_name = StringField(
        "Organization Name",
        validators=[InputRequired(message="Organization name is required"), Length(max=255)],
    )
    admin_name = StringField(
        "Admin Full Name",
        validators=[InputRequired(message="Full name is required"), Length(max=255)],
    )
    admin_email = StringField(
        "Admin Email",
        validators=[InputRequired(message="Email is required"), Email(), Length(max=255)],
    )
    admin_password = PasswordField(
        "Admin Password",
        validators=[InputRequired(), Length(min=12, max=128), _validate_strong_password],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[InputRequired(), EqualTo("admin_password", message="Passwords must match")],
    )
    submit = SubmitField("Create Organization")


class OrganizationSettingsForm(FlaskForm):
    organization_name = StringField(
        "Organization Name",
        validators=[InputRequired(message="Organization name is required"), Length(max=255)],
    )
    submit = SubmitField("Save Organization")


class UserUpdateForm(FlaskForm):
    name = StringField(
        "Full Name",
        validators=[InputRequired(message="Name is required"), Length(max=255)],
    )
    email = StringField(
        "Email",
        validators=[InputRequired(message="Email is required"), Email(), Length(max=255)],
    )
    role = SelectField(
        "Role",
        choices=[(UserRole.ADMIN.value, "Admin"), (UserRole.USER.value, "User")],
        validators=[InputRequired()],
    )
    active = BooleanField("Active")
    submit = SubmitField("Save Changes")


class ForgotPasswordForm(FlaskForm):
    organization_slug = StringField(
        "Organization Slug",
        validators=[InputRequired(), Length(max=128)],
    )
    email = StringField(
        "Email",
        validators=[InputRequired(), Email(), Length(max=255)],
    )
    submit = SubmitField("Send Reset Link")


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[InputRequired(), Length(min=12, max=128)],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[InputRequired(), EqualTo("password", message="Passwords must match")],
    )
    submit = SubmitField("Reset Password")


class OTPVerificationForm(FlaskForm):
    otp_code = StringField(
        "Verification Code",
        validators=[
            InputRequired(message="Enter the 6-digit code"),
            Length(min=6, max=6, message="OTP must be 6 digits"),
            Regexp(r"^[0-9]{6}$", message="Digits only"),
        ],
    )
    submit = SubmitField("Verify")


class ResendOtpForm(FlaskForm):
    submit = SubmitField("Resend Code")


class EquipmentForm(FlaskForm):
    name = StringField(
        "Equipment Name",
        validators=[InputRequired(message="Name is required"), Length(max=255)],
    )
    category = StringField(
        "Category",
        validators=[InputRequired(message="Category is required"), Length(max=128)],
    )
    serial_number = StringField("Serial Number", validators=[Optional(), Length(max=128)])
    department = StringField("Department", validators=[Optional(), Length(max=128)])
    location = StringField("Location", validators=[Optional(), Length(max=255)])
    purchase_date = DateField("Purchase Date", validators=[Optional()], format="%Y-%m-%d")
    warranty_expiry = DateField("Warranty Expiry", validators=[Optional()], format="%Y-%m-%d")
    maintenance_team_id = SelectField("Maintenance Team", coerce=int, validators=[Optional()], default=0)
    assigned_to_user_id = SelectField("Assigned Technician", coerce=int, validators=[Optional()], default=0)
    status = SelectField(
        "Status",
        choices=[
            (EquipmentStatus.ACTIVE.value, "Active"),
            (EquipmentStatus.MAINTENANCE.value, "Under Maintenance"),
            (EquipmentStatus.OUT_OF_SERVICE.value, "Out of Service"),
            (EquipmentStatus.SCRAPPED.value, "Scrapped"),
        ],
        validators=[InputRequired()],
        default=EquipmentStatus.ACTIVE.value,
    )
    submit = SubmitField("Save Equipment")

    def validate_warranty_expiry(self, field) -> None:  # type: ignore[override]
        if field.data and self.purchase_date.data and field.data < self.purchase_date.data:
            raise ValidationError("Warranty expiry cannot be earlier than purchase date.")


class MaintenanceTeamForm(FlaskForm):
    team_name = StringField(
        "Team Name",
        validators=[InputRequired(message="Team name is required"), Length(max=255)],
    )
    description = TextAreaField("Description", validators=[Optional(), Length(max=1000)])
    submit = SubmitField("Save Team")


class TechnicianAssignmentForm(FlaskForm):
    user_id = SelectField("Technician", coerce=int, validators=[InputRequired()])
    submit = SubmitField("Add Technician")


class MaintenanceRequestForm(FlaskForm):
    subject = StringField(
        "Subject",
        validators=[InputRequired(message="Subject is required"), Length(max=255)],
    )
    description = TextAreaField("Description", validators=[Optional(), Length(max=2000)])
    request_type = SelectField(
        "Request Type",
        choices=[(RequestType.PREVENTIVE.value, "Preventive"), (RequestType.CORRECTIVE.value, "Breakdown / Corrective")],
        validators=[InputRequired()],
    )
    priority = SelectField(
        "Priority",
        choices=[("high", "High"), ("normal", "Normal"), ("low", "Low")],
        validators=[InputRequired()],
        default="normal",
    )
    equipment_id = SelectField("Equipment", coerce=int, validators=[InputRequired()])
    scheduled_date = DateField("Scheduled Date", validators=[Optional()], format="%Y-%m-%d")
    submit = SubmitField("Save Request")

    def validate_scheduled_date(self, field) -> None:  # type: ignore[override]
        req_type = RequestType(self.request_type.data)
        if req_type == RequestType.PREVENTIVE and not field.data:
            raise ValidationError("Scheduled date is required for preventive maintenance.")


class MaintenanceStatusForm(FlaskForm):
    transition = SelectField(
        "Transition",
        choices=[
            (MaintenanceStatus.IN_PROGRESS.value, "Start Work"),
            (MaintenanceStatus.REPAIRED.value, "Mark Repaired"),
            (MaintenanceStatus.SCRAP.value, "Mark Scrap"),
        ],
        validators=[InputRequired()],
    )
    submit = SubmitField("Update Status")


class MaintenanceTechnicianAssignForm(FlaskForm):
    technician_id = SelectField("Technician", coerce=int, validators=[InputRequired()])
    submit = SubmitField("Assign Technician")


class SubscriptionCheckoutForm(FlaskForm):
    total_members = IntegerField(
        "Total Members",
        validators=[InputRequired(message="Enter desired member capacity")],
        default=5,
    )
    razorpay_order_id = HiddenField()
    submit = SubmitField("Proceed to Payment")

    def validate_total_members(self, field) -> None:  # type: ignore[override]
        if field.data is None or field.data < 1:
            raise ValidationError("Member capacity must be at least 1.")


class SuperAdminOrgActionForm(FlaskForm):
    action = HiddenField(validators=[InputRequired(), Length(max=64)])
    seats = IntegerField("Seats", validators=[Optional()])
    extend_days = IntegerField("Extend Days", validators=[Optional()])
    note = TextAreaField("Reason", validators=[Optional(), Length(max=500)])
    submit = SubmitField("Apply")


class SuperAdminUserActionForm(FlaskForm):
    action = HiddenField(validators=[InputRequired(), Length(max=64)])
    note = TextAreaField("Reason", validators=[Optional(), Length(max=500)])
    submit = SubmitField("Apply")


class SuperAdminSecurityActionForm(FlaskForm):
    action = StringField("Action", validators=[InputRequired(), Length(max=64)])
    target = StringField("Target", validators=[Optional(), Length(max=255)])
    note = TextAreaField("Reason", validators=[Optional(), Length(max=500)])
    submit = SubmitField("Execute")


class SupportRequestForm(FlaskForm):
    full_name = StringField(
        "Full Name",
        validators=[InputRequired(message="Name is required"), Length(min=2, max=255)],
    )
    email = StringField(
        "Email",
        validators=[InputRequired(message="Email is required"), Email(), Length(max=255)],
    )
    subject = StringField(
        "Subject",
        validators=[InputRequired(message="Subject is required"), Length(min=5, max=255)],
    )
    category = SelectField(
        "Support Category",
        choices=[
            (SupportCategory.ACCOUNT.value, "Account & Login Issues"),
            (SupportCategory.BILLING.value, "Billing & Payments / Subscription Help"),
            (SupportCategory.TECHNICAL.value, "Technical Support / Bugs"),
            (SupportCategory.FEATURE.value, "Feature Request / Product Feedback"),
            (SupportCategory.TEAM.value, "Organization / Team Management Issues"),
            (SupportCategory.MAINTENANCE.value, "Maintenance System Support"),
            (SupportCategory.SECURITY.value, "Security / Abuse Reporting"),
            (SupportCategory.OTHER.value, "Other (General Inquiry)"),
        ],
        validators=[InputRequired(message="Select a category")],
    )
    organization = StringField(
        "Organization",
        validators=[Optional(), Length(max=255)],
        description="If you are contacting on behalf of a company",
    )
    message = TextAreaField(
        "Message",
        validators=[InputRequired(message="Please describe the request"), Length(min=20, max=4000)],
    )
    submit = SubmitField("Submit Request")
