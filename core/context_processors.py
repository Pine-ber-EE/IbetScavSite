from django.conf import settings
from hunt.settings import HUNT_YEAR

def hunt_settings(request):
    """Make certain hunt settings available in all templates."""
    return {
        'HUNT_YEAR': HUNT_YEAR,
    }
