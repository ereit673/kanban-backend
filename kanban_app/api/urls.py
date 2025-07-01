from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_nested.routers import NestedDefaultRouter

from kanban_app.api import views

urlpatterns = [
    path('login/', views.LoginAPIView.as_view(), name='login'),
    path('email-check/', views.EmailCheckAPIView.as_view(), name='email-check'),
]

router = DefaultRouter()
router.register(r'boards', views.BoardViewSet, basename='boards')
router.register(r'tasks', views.TaskViewSet, basename='tasks')
router.register(r'register', views.RegisterViewSet, basename='register')

tasks_router = NestedDefaultRouter(router, r'tasks', lookup='task')
tasks_router.register(r'comments', views.CommentViewSet, basename='task-comments')

urlpatterns += router.urls + tasks_router.urls
