from django.urls import path

from . import views

app_name = "core"

urlpatterns = [
    path("", views.login_view, name="login"),
    path("auth/ion/", views.oauth_start, name="oauth_start"),
    path("complete/ion/", views.oauth_callback, name="oauth_callback"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("challenge/", views.challenge_view, name="challenge"),
    path(
        "challenge/<slug:challenge_slug>/submit/",
        views.submit_challenge,
        name="submit_challenge",
    ),
    path(
        "challenge/<slug:challenge_slug>/move/<str:direction>/",
        views.move_challenge,
        name="move_challenge",
    ),
    path("analytics/", views.analytics_view, name="analytics"),
    path("analytics/switch-class/", views.switch_class_view, name="switch_class"),
    path("logout/", views.logout_view, name="logout"),
]
