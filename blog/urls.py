from django.urls import path
from .views import (index, about, add_post,
                    post_list, post_detail, post_edit,
                    post_delete)

app_name = 'blog'
urlpatterns = [
    path('', index, name='index'),
    path('about/', about, name='about'),
    path('posts/add/', add_post, name='add_post'),
    path('posts/', post_list, name='post_list'),
    path('posts/<slug:slug>/', post_detail, name='post_detail'),
    path('posts/<int:pk>/edit/', post_edit, name='post_edit'),
    path('posts/<int:pk>/delete/', post_delete, name='post_delete'),
]
