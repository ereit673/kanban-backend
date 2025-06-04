from django.db import models
from django.contrib.auth.models import User


class Board(models.Model):
    title = models.CharField(max_length=255)
    owner = models.ForeignKey(User, related_name='owned_boards', on_delete=models.CASCADE)
    users = models.ManyToManyField(User, related_name='boards')
    
    def __str__(self):
        return self.title
    
    
class Task(models.Model):
    PRIORITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High')
    ]
    
    STATUS_CHOICES = [
        ('To-Do', 'To-Do'),
        ('In-Progress', 'In-Progress'),
        ('Review', 'Review'),
        ('Done', 'Done'),
    ]
    
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='Medium')
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='To-Do')
    due_date = models.DateField(null=True, blank=True)
    
    board = models.ForeignKey(Board, related_name='tasks', on_delete=models.CASCADE)
    assignee = models.ForeignKey(User, related_name='assigned_tasks', null=True, blank=True, on_delete=models.SET_NULL)
    reviewer = models.ForeignKey(User, related_name='review_tasks', null=True, blank=True, on_delete=models.SET_NULL)
    
    def __str__(self):
        return self.title
    

class Comment(models.Model):
    task = models.ForeignKey(Task, related_name='comments', on_delete=models.CASCADE)
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    content = models.TextField()
    
    def __str__(self):
        return f"Comment by {self.author.username} on {self.task.title}"
