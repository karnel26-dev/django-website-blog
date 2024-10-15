from django.contrib.auth import get_user_model
from django.db import models
from django.urls import reverse
from django.utils import timezone
# from django.utils.text import slugify
from slugify import slugify

User = get_user_model()


class Post(models.Model):
    # author = models.CharField(max_length=50, verbose_name="Автор")
    author = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Автор")
    title = models.CharField(max_length=200, verbose_name="Заголовок")
    text = models.TextField(verbose_name="Текст поста")
    created_at = models.DateTimeField(default=timezone.now, verbose_name='Опубликовано', editable=False)
    image = models.ImageField(upload_to='posts/', null=True, verbose_name='Изображение')
    slug = models.SlugField(max_length=200, unique=True, editable=False, null=True)

    def save(self, *args, **kwargs):
        self.slug = slugify(self.title)
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('blog:post_detail', kwargs={'slug': self.slug})

    class Meta:
        # имя таблицы в единств. числе
        verbose_name = "Пост"
        # имя таблицы во множеств. чисде
        verbose_name_plural = "Посты"

    def __str__(self):
        return self.title
