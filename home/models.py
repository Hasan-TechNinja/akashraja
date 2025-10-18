from django.db import models

# Create your models here.

class Category(models.Model):
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='categories/')
    
    def __str__(self):
        return self.name
    
class Option(models.Model):
    category = models.ForeignKey(Category, related_name='options', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='options/')

    def __str__(self):
        return f"{self.name} ({self.category.name})"