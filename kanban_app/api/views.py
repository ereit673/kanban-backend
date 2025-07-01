from django.db.models import Count, Q

from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from kanban_app.models import Board, Task, Comment
from django.contrib.auth.models import User
from .serializers import BoardCreateSerializer, BoardListSerializer, BoardDetailSerializer, BoardUpdateSerializer, TaskSerializer, TaskDetailSerializer, TaskCreateSerializer, TaskUpdateSerializer, CommentSerializer, RegisterSerializer


from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import NotAuthenticated, NotFound, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action


from django.contrib.auth import authenticate
from .serializers import LoginSerializer


class BoardViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return BoardDetailSerializer
        elif self.action == 'list':
            return BoardListSerializer
        elif self.action == 'create':
            return BoardCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return BoardUpdateSerializer
        return BoardListSerializer  # fallback

    def get_queryset(self):
        user = self.request.user
        return (
            Board.objects.filter(Q(owner=user) | Q(users=user)).distinct().annotate(
                member_count=Count('users', distinct=True),
                ticket_count=Count('tasks', distinct=True),
                tasks_to_do_count=Count('tasks', filter=Q(
                    tasks__status='To-Do'), distinct=True),
                tasks_high_prio_count=Count('tasks', filter=Q(
                    tasks__priority='High'), distinct=True)
            )
        )

    def perform_create(self, serializer):
        board = serializer.save(owner=self.request.user)
        board.users.add(self.request.user)

    def update(self, request, *args, **kwargs):
        board = self.get_object()
        user = request.user

        # Permissions: must be owner or member
        if user != board.owner and user not in board.users.all():
            raise PermissionDenied(
                "You must be the owner or a member of the board.")

        serializer = self.get_serializer(
            board, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated_board = serializer.save()

        return Response(BoardUpdateSerializer(updated_board).data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        board = self.get_object()
        if board.owner != request.user:
            raise PermissionDenied(
                "Nur der Eigentümer darf dieses Board löschen.")
        board.delete()
        return Response(
            {"detail": "Board wurde erfolgreich gelöscht."},
            status=status.HTTP_204_NO_CONTENT
        )


class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'create':
            return TaskCreateSerializer
        elif self.action in ['assigned_to_me', 'reviewing']:
            return TaskDetailSerializer
        elif self.action == 'partial_update':
            return TaskUpdateSerializer
        return TaskSerializer

    def destroy(self, request, *args, **kwargs):
        task = self.get_object()
        user = request.user

        if not (task.assignee == user or task.board.owner == user):
            raise PermissionDenied(
                "Verboten. Nur der Ersteller der Task oder der Board-Eigentümer kann die Task löschen.")

        try:
            self.perform_destroy(task)
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception:
            return Response(
                {"detail": "Interner Serverfehler."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'], url_path='assigned-to-me')
    def assigned_to_me(self, request):
        user = request.user

        if not user or not user.is_authenticated:
            raise NotAuthenticated(
                "Nicht autorisiert. Der Benutzer muss eingeloggt sein.")

        try:
            tasks = Task.objects.filter(
                assignee=user).prefetch_related('comments')
            serializer = self.get_serializer(tasks, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception:
            return Response(
                {"detail": "Interner Serverfehler."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'], url_path='reviewing')
    def reviewing(self, request):
        user = request.user

        if not user or not user.is_authenticated:
            raise NotAuthenticated(
                "Nicht autorisiert. Der Benutzer muss eingeloggt sein.")

        try:
            tasks = Task.objects.filter(
                reviewer=user).prefetch_related('comments')
            serializer = self.get_serializer(tasks, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception:
            return Response(
                {"detail": "Interner Serverfehler."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            

class CommentViewSet(viewsets.ModelViewSet):
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        task_id = self.kwargs.get('task_pk')
        try:
            task = Task.objects.get(pk=task_id)
        except Task.DoesNotExist:
            raise NotFound("Task nicht gefunden.")

        user = self.request.user
        if not task.board.users.filter(id=user.id).exists() and task.board.owner != user:
            raise PermissionDenied("Verboten. Der Benutzer muss Mitglied des Boards sein.")

        return Comment.objects.filter(task=task).order_by('created_at')

    def perform_create(self, serializer):
        task_id = self.kwargs.get('task_pk')
        try:
            task = Task.objects.get(pk=task_id)
        except Task.DoesNotExist:
            raise NotFound("Task nicht gefunden.")

        user = self.request.user
        if not task.board.users.filter(id=user.id).exists() and task.board.owner != user:
            raise PermissionDenied("Verboten. Der Benutzer muss Mitglied des Boards sein.")

        serializer.save(task=task, author=user)
        
    def destroy(self, request, *args, **kwargs):
        user = request.user
        task_id = self.kwargs.get('task_pk')
        comment_id = self.kwargs.get('pk')

        try:
            task = Task.objects.get(pk=task_id)
        except Task.DoesNotExist:
            return Response({"detail": "Task nicht gefunden."}, status=status.HTTP_404_NOT_FOUND)

        try:
            comment = Comment.objects.get(pk=comment_id, task=task)
        except Comment.DoesNotExist:
            return Response({"detail": "Kommentar nicht gefunden."}, status=status.HTTP_404_NOT_FOUND)

        if comment.author != user:
            return Response({"detail": "Verboten. Nur der Ersteller des Kommentars darf ihn löschen."}, status=status.HTTP_403_FORBIDDEN)

        try:
            comment.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception:
            return Response({"detail": "Interner Serverfehler."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RegisterViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]
    http_method_names = ['post']


class LoginAPIView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)

        return Response({
            'token': str(refresh.access_token),
            'fullname': user.get_full_name(),
            'email': user.email,
            'user_id': user.id
        }, status=status.HTTP_200_OK)


class EmailCheckAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        email = request.query_params.get('email')

        if not email:
            return Response(
                {"detail": "Ungültige Anfrage. Die E-Mail-Adresse fehlt oder hat ein falsches Format."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
            data = {
                "id": user.id,
                "email": user.email,
                "fullname": user.get_full_name() or user.username
            }
            return Response(data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(
                {"detail": "Email nicht gefunden. Die Email existiert nicht."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception:
            return Response(
                {"detail": "Interner Serverfehler."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
