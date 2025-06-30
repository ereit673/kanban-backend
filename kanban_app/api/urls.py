from django.urls import path

from kanban_app.api import views
from rest_framework.routers import DefaultRouter


urlpatterns = [
    path('login/', views.LoginAPIView.as_view(), name='login'),
]

router = DefaultRouter()
router.register(r'boards', views.BoardViewSet)
router.register(r'tasks', views.TaskViewSet)
router.register(r'register', views.RegisterViewSet, basename='register')

urlpatterns += router.urls
