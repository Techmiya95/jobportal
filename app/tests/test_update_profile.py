import json
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User

class UpdateProfileTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    def test_update_profile(self):
        response = self.client.post(reverse('update_profile'), {
            'username': 'newusername',
            'email': 'newemail@example.com',
            'father_name': 'John Doe',
            'ug_college': 'XYZ University',
            'branch': 'Computer Science',
            'passout_year': '2023',
            'grad_percentage': '85',
            'tenth_percentage': '90',
            'twelfth_percentage': '88',
        })
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(response.content, {
            "success": True,
            "data": {
                "username": "newusername",
                "email": "newemail@example.com",
                "father_name": "John Doe",
                "ug_college": "XYZ University",
                "branch": "Computer Science",
                "passout_year": "2023",
                "grad_percentage": "85",
                "tenth_percentage": "90",
                "twelfth_percentage": "88",
            },
            "completion_percentage": 100,
        })
