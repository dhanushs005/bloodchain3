from django.db import models
from django.core.validators import RegexValidator

class UserDetails(models.Model):
    name = models.CharField(max_length=100)
    mobile = models.CharField(max_length=10)
    age = models.PositiveIntegerField()
    bg = models.CharField(
        max_length=10,
        choices=[
            ('A1+', 'A1+'),
            ('A1-', 'A1-'),
            ('A+', 'A+'),
            ('A-', 'A-'),
            ('B+', 'B+'),
            ('B-', 'B-'),
            ('O+', 'O+'),
            ('O-', 'O-'),
            ('Select', 'Select'),
        ],
        default='Select',
        validators=[
            RegexValidator(
                regex=r'^(?!Select$).*',
                message="Select a valid blood type",
            )
        ],
    )
    gender = models.CharField(
        max_length=50,
        choices=[
            ('Male', 'Male'),
            ('Female', 'Female'),
            ('Others', 'Others'),
            ('Select', 'Select'),
        ],
        default='Select',
        validators=[
            RegexValidator(
                regex=r'^(?!Select$).*',
                message="Select a valid gender",
            )
        ],
    )
    dists = models.CharField(
        max_length=100,
        choices=[
            ('Ariyalur', 'Ariyalur'),
            ('Chengalpattu', 'Chengalpattu'),
            ('Chennai', 'Chennai'),
            ('Coimbatore', 'Coimbatore'),
            ('Cuddalore', 'Cuddalore'),
            ('Dharmapuri', 'Dharmapuri'),
            ('Dindigul', 'Dindigul'),
            ('Erode', 'Erode'),
            ('Kallakurichi', 'Kallakurichi'),
            ('Kancheepuram', 'Kancheepuram'),
            ('Karur', 'Karur'),
            ('Krishnagiri', 'Krishnagiri'),
            ('Madurai', 'Madurai'),
            ('Mayiladuthurai', 'Mayiladuthurai'),
            ('Nagapattinam', 'Nagapattinam'),
            ('Namakkal', 'Namakkal'),
            ('Nilgiris', 'Nilgiris'),
            ('Perambalur', 'Perambalur'),
            ('Pudukkottai', 'Pudukkottai'),
            ('Ramanathapuram', 'Ramanathapuram'),
            ('Ranipet', 'Ranipet'),
            ('Salem', 'Salem'),
            ('Sivaganga', 'Sivaganga'),
            ('Tenkasi', 'Tenkasi'),
            ('Thanjavur', 'Thanjavur'),
            ('Theni', 'Theni'),
            ('Thoothukudi', 'Thoothukudi'),
            ('Tiruchirappalli', 'Tiruchirappalli'),
            ('Tirunelveli', 'Tirunelveli'),
            ('Tirupathur', 'Tirupathur'),
            ('Tiruppur', 'Tiruppur'),
            ('Tiruvallur', 'Tiruvallur'),
            ('Tiruvannamalai', 'Tiruvannamalai'),
            ('Tiruvarur', 'Tiruvarur'),
            ('Vellore', 'Vellore'),
            ('Viluppuram', 'Viluppuram'),
            ('Virudhunagar', 'Virudhunagar'),
            ('Select', 'Select'),
        ],
        default='Select',
        validators=[
            RegexValidator(
                regex=r'^(?!Select$).*',
                message="Select a valid district",
            )
        ],
    )
    last_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return self.name


class EmergencyDetails(models.Model):
    pname = models.CharField(max_length=100)
    pmobile = models.CharField(max_length=10)
    hospital_name = models.CharField(max_length=300)
    bg_needed = models.CharField(
        max_length=10,
        choices=[
            ('A1+', 'A1+'),
            ('A1-', 'A1-'),
            ('A+', 'A+'),
            ('A-', 'A-'),
            ('B+', 'B+'),
            ('B-', 'B-'),
            ('O+', 'O+'),
            ('O-', 'O-'),
            ('Select', 'Select'),
        ],
        default='Select',
        validators=[
            RegexValidator(
                regex=r'^(?!Select$).*',
                message="Select a valid blood type",
            )
        ],
    )
    pgender = models.CharField(
        max_length=50,
        choices=[
            ('Male', 'Male'),
            ('Female', 'Female'),
            ('Others', 'Others'),
            ('Select', 'Select'),
        ],
        default='Select',
        validators=[
            RegexValidator(
                regex=r'^(?!Select$).*',
                message="Select a valid gender",
            )
        ],
    )
    pdists = models.CharField(
        max_length=100,
        choices=[
            ('Ariyalur', 'Ariyalur'),
            ('Chengalpattu', 'Chengalpattu'),
            ('Chennai', 'Chennai'),
            ('Coimbatore', 'Coimbatore'),
            ('Cuddalore', 'Cuddalore'),
            ('Dharmapuri', 'Dharmapuri'),
            ('Dindigul', 'Dindigul'),
            ('Erode', 'Erode'),
            ('Kallakurichi', 'Kallakurichi'),
            ('Kancheepuram', 'Kancheepuram'),
            ('Karur', 'Karur'),
            ('Krishnagiri', 'Krishnagiri'),
            ('Madurai', 'Madurai'),
            ('Mayiladuthurai', 'Mayiladuthurai'),
            ('Nagapattinam', 'Nagapattinam'),
            ('Namakkal', 'Namakkal'),
            ('Nilgiris', 'Nilgiris'),
            ('Perambalur', 'Perambalur'),
            ('Pudukkottai', 'Pudukkottai'),
            ('Ramanathapuram', 'Ramanathapuram'),
            ('Ranipet', 'Ranipet'),
            ('Salem', 'Salem'),
            ('Sivaganga', 'Sivaganga'),
            ('Tenkasi', 'Tenkasi'),
            ('Thanjavur', 'Thanjavur'),
            ('Theni', 'Theni'),
            ('Thoothukudi', 'Thoothukudi'),
            ('Tiruchirappalli', 'Tiruchirappalli'),
            ('Tirunelveli', 'Tirunelveli'),
            ('Tirupathur', 'Tirupathur'),
            ('Tiruppur', 'Tiruppur'),
            ('Tiruvallur', 'Tiruvallur'),
            ('Tiruvannamalai', 'Tiruvannamalai'),
            ('Tiruvarur', 'Tiruvarur'),
            ('Vellore', 'Vellore'),
            ('Viluppuram', 'Viluppuram'),
            ('Virudhunagar', 'Virudhunagar'),
            ('Select', 'Select'),
        ],
        default='Select',
        validators=[
            RegexValidator(
                regex=r'^(?!Select$).*',
                message="Select a valid district",
            )
        ],
    )
    units_needed = models.PositiveIntegerField(
    	default='1'
    	)
    urgency_level=models.CharField(
    	max_length=100,
    	choices=[
    	('Immediate','Immediate'),
    	('Within 24 hours','Within 24 hours'),
    	('Within 3 days','Within 3 days'),
    	],
    	default='Immediate',
    	)
    def __str__(self):
        return self.pname
