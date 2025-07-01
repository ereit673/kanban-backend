from rest_framework import serializers
from kanban_app.models import Board, Task, Comment
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed


class BoardCreateSerializer(serializers.ModelSerializer):
    members = serializers.ListField(
        child=serializers.IntegerField(), write_only=True
    )
    
    class Meta:
        model = Board
        fields = ['id', 'title', 'members']
        
    def validate_members(self, value):
        existing_user_ids = set(User.objects.filter(id__in=value).values_list('id', flat=True))
        invalid_ids = set(value) - existing_user_ids
        if invalid_ids:
            raise serializers.ValidationError(f"Invalid user IDs: {list(invalid_ids)}")
        return value

    def create(self, validated_data):
        members = validated_data.pop('members', [])
        user = self.context['request'].user

        board = Board.objects.create(title=validated_data['title'], owner=user)
        board.users.add(user)
        board.users.add(*User.objects.filter(id__in=members).exclude(id=user.id))

        return board

    def to_representation(self, instance):
        return {
            "id": instance.id,
            "title": instance.title,
            "member_count": instance.users.count(),
            "ticket_count": instance.tasks.count(),
            "tasks_to_do_count": instance.tasks.filter(status='To-Do').count(),
            "tasks_high_prio_count": instance.tasks.filter(priority='High').count(),
            "owner_id": instance.owner.id
        }



class BoardListSerializer(serializers.ModelSerializer):
    member_count = serializers.IntegerField()
    ticket_count = serializers.IntegerField()
    tasks_to_do_count = serializers.IntegerField()
    tasks_high_prio_count = serializers.IntegerField()
    owner_id = serializers.IntegerField(source='owner.id')

    class Meta:
        model = Board
        fields = [
            'id', 
            'title', 
            'owner_id',
            'member_count', 
            'ticket_count',
            'tasks_to_do_count', 
            'tasks_high_prio_count'
        ]


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = '__all__'


class RegisterSerializer(serializers.ModelSerializer):
    fullname = serializers.CharField(write_only=True)
    repeated_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'repeated_password', 'fullname']
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True}
        }

    def validate(self, data):
        if data['password'] != data['repeated_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        fullname = validated_data.pop('fullname')
        validated_data.pop('repeated_password')

        name_parts = fullname.split(' ', 1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ''

        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=first_name,
            last_name=last_name
        )
        return user

    def to_representation(self, instance):
        token = RefreshToken.for_user(instance)
        return {
            'token': str(token.access_token),
            'fullname': instance.get_full_name(),
            'email': instance.email,
            'user_id': instance.id,
        }


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError('Invalid credentials')

            user = authenticate(username=user.username, password=password)
            if user is None:
                raise serializers.ValidationError('Invalid credentials')

        else:
            raise serializers.ValidationError(
                'Must include email and password.')

        data['user'] = user
        return data


class UserBasicSerializer(serializers.ModelSerializer):
    fullname = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'email', 'fullname']
        
    def get_fullname(self, obj):
        return obj.get_full_name() or obj.username
    
    
class TaskDetailSerializer(serializers.ModelSerializer):
    assignee = UserBasicSerializer(read_only=True)
    reviewer = UserBasicSerializer(read_only=True)
    comments_count = serializers.IntegerField(source='comments.count', read_only=True)

    class Meta:
        model = Task
        fields = [
            'id', 'title', 'description', 'status', 'priority',
            'assignee', 'reviewer', 'due_date', 'comments_count'
        ]
        
        
class BoardDetailSerializer(serializers.ModelSerializer):
    owner_id = serializers.IntegerField(source='owner.id', read_only=True)
    members = UserBasicSerializer(source='users', many=True, read_only=True)
    tasks = TaskDetailSerializer(many=True, read_only=True)

    class Meta:
        model = Board
        fields = ['id', 'title', 'owner_id', 'members', 'tasks']
        
        
class BoardUpdateSerializer(serializers.ModelSerializer):
    members = serializers.ListField(
        child=serializers.IntegerField(), write_only=True, required=False
    )
    title = serializers.CharField(required=False)

    class Meta:
        model = Board
        fields = ['title', 'members']

    def validate_members(self, value):
        existing_user_ids = set(User.objects.filter(id__in=value).values_list('id', flat=True))
        invalid_ids = set(value) - existing_user_ids
        if invalid_ids:
            raise serializers.ValidationError(f"Invalid user IDs: {list(invalid_ids)}")
        return value

    def update(self, instance, validated_data):
        if 'title' in validated_data:
            instance.title = validated_data['title']

        if 'members' in validated_data:
            members = validated_data['members']
            instance.users.set(User.objects.filter(id__in=members + [instance.owner.id]))

        instance.save()
        return instance

    def to_representation(self, instance):
        return {
            "id": instance.id,
            "title": instance.title,
            "owner_data": {
                "id": instance.owner.id,
                "email": instance.owner.email,
                "fullname": instance.owner.get_full_name()
            },
            "members_data": [
                {
                    "id": user.id,
                    "email": user.email,
                    "fullname": user.get_full_name()
                }
                for user in instance.users.all()
            ]
        }