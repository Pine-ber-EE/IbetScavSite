from django.conf import settings
from hunt.settings import HUNT_YEAR, ENABLE_SNOW_OVERLAY


def hunt_settings(request):
    """Make certain hunt settings available in all templates."""
    return {
        "HUNT_YEAR": HUNT_YEAR,
        "ENABLE_SNOW_OVERLAY": ENABLE_SNOW_OVERLAY,
    }
