from django import forms

class UserForm(forms.Form):
    name = forms.CharField(
        label="Name",
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    mobile = forms.CharField(
        label="Mobile",
        max_length=10,
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    bg = forms.ChoiceField(
        label="Blood Group",
        choices=[
            ('A1+', 'A1+'), ('A1-', 'A1-'), ('A+', 'A+'), ('A-', 'A-'),
            ('B+', 'B+'), ('B-', 'B-'), ('O+', 'O+'), ('O-', 'O-')
        ],
        widget=forms.Select(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    gender = forms.ChoiceField(
        label="Gender",
        choices=[('Male', 'Male'), ('Female', 'Female'), ('Others', 'Others')],
        widget=forms.Select(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    dists = forms.ChoiceField(
        label="District",
        choices=[
            ('Ariyalur', 'Ariyalur'), ('Chengalpattu', 'Chengalpattu'),
            ('Chennai', 'Chennai'), ('Coimbatore', 'Coimbatore'),
            ('Cuddalore', 'Cuddalore'), ('Dharmapuri', 'Dharmapuri'),
            ('Dindigul', 'Dindigul'), ('Erode', 'Erode'),
            ('Kallakurichi', 'Kallakurichi'), ('Kancheepuram', 'Kancheepuram'),
            ('Karur', 'Karur'), ('Krishnagiri', 'Krishnagiri'),
            ('Madurai', 'Madurai'), ('Mayiladuthurai', 'Mayiladuthurai'),
            ('Nagapattinam', 'Nagapattinam'), ('Namakkal', 'Namakkal'),
            ('Nilgiris', 'Nilgiris'), ('Perambalur', 'Perambalur'),
            ('Pudukkottai', 'Pudukkottai'), ('Ramanathapuram', 'Ramanathapuram'),
            ('Ranipet', 'Ranipet'), ('Salem', 'Salem'),
            ('Sivaganga', 'Sivaganga'), ('Tenkasi', 'Tenkasi'),
            ('Thanjavur', 'Thanjavur'), ('Theni', 'Theni'),
            ('Thoothukudi', 'Thoothukudi'), ('Tiruchirappalli', 'Tiruchirappalli'),
            ('Tirunelveli', 'Tirunelveli'), ('Tirupathur', 'Tirupathur'),
            ('Tiruppur', 'Tiruppur'), ('Tiruvallur', 'Tiruvallur'),
            ('Tiruvannamalai', 'Tiruvannamalai'), ('Tiruvarur', 'Tiruvarur'),
            ('Vellore', 'Vellore'), ('Viluppuram', 'Viluppuram'),
            ('Virudhunagar', 'Virudhunagar'),
        ],
        widget=forms.Select(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    last_date = forms.DateField(
        label="Last Donated Date",
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )

class EmergencyForm(forms.Form):
    pname = forms.CharField(
        label="Patient Name",
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    pmobile = forms.CharField(
        label="Mobile",
        max_length=10,
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    bg_needed = forms.ChoiceField(
        label="Blood Group needed ",
        choices=[
            ('A1+', 'A1+'), ('A1-', 'A1-'), ('A+', 'A+'), ('A-', 'A-'),
            ('B+', 'B+'), ('B-', 'B-'), ('O+', 'O+'), ('O-', 'O-')
        ],
        widget=forms.Select(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    pgender = forms.ChoiceField(
        label="Gender",
        choices=[('Male', 'Male'), ('Female', 'Female'), ('Others', 'Others')],
        widget=forms.Select(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    units_needed = forms.CharField(
        label="Units Needed",
        max_length=10,
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )

    hospital_name = forms.CharField(
        label="Hospital Name",
        max_length=300,
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    pdists = forms.ChoiceField(
        label="District",
        choices=[
            ('Ariyalur', 'Ariyalur'), ('Chengalpattu', 'Chengalpattu'),
            ('Chennai', 'Chennai'), ('Coimbatore', 'Coimbatore'),
            ('Cuddalore', 'Cuddalore'), ('Dharmapuri', 'Dharmapuri'),
            ('Dindigul', 'Dindigul'), ('Erode', 'Erode'),
            ('Kallakurichi', 'Kallakurichi'), ('Kancheepuram', 'Kancheepuram'),
            ('Karur', 'Karur'), ('Krishnagiri', 'Krishnagiri'),
            ('Madurai', 'Madurai'), ('Mayiladuthurai', 'Mayiladuthurai'),
            ('Nagapattinam', 'Nagapattinam'), ('Namakkal', 'Namakkal'),
            ('Nilgiris', 'Nilgiris'), ('Perambalur', 'Perambalur'),
            ('Pudukkottai', 'Pudukkottai'), ('Ramanathapuram', 'Ramanathapuram'),
            ('Ranipet', 'Ranipet'), ('Salem', 'Salem'),
            ('Sivaganga', 'Sivaganga'), ('Tenkasi', 'Tenkasi'),
            ('Thanjavur', 'Thanjavur'), ('Theni', 'Theni'),
            ('Thoothukudi', 'Thoothukudi'), ('Tiruchirappalli', 'Tiruchirappalli'),
            ('Tirunelveli', 'Tirunelveli'), ('Tirupathur', 'Tirupathur'),
            ('Tiruppur', 'Tiruppur'), ('Tiruvallur', 'Tiruvallur'),
            ('Tiruvannamalai', 'Tiruvannamalai'), ('Tiruvarur', 'Tiruvarur'),
            ('Vellore', 'Vellore'), ('Viluppuram', 'Viluppuram'),
            ('Virudhunagar', 'Virudhunagar'),
        ],
        widget=forms.Select(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    urgency_level = forms.ChoiceField(
        label="Urgency Level",
        choices=[('Immediate', 'Immediate'), ('Within 24 hours', 'Within 24 hours'), ('Within 3 days', 'Within 3 days')],
        widget=forms.Select(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
class ReportForm(forms.Form):
    report_type = forms.CharField(
        max_length=100,
        label='Report Type',
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )

    description = forms.CharField(
        label='Description',
        widget=forms.Textarea(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400',
            'rows': 4  # Optional: Adjust the number of rows for the textarea
        })
    )

    rmobile = forms.CharField(
        label="Mobile",
        max_length=10,
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=100,
        label='Username',
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    password = forms.CharField(
        max_length=100,
        label='Password',
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
class SignupForm(forms.Form):
    username = forms.CharField(
        max_length=100,
        label='Username',
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
    password = forms.CharField(
        max_length=100,
        label='Password',
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400'
        })
    )
