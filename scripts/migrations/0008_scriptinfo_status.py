# Generated by Django 4.1 on 2023-09-10 11:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scripts', '0007_remove_scriptinfo_status_alter_scriptinfo_arguments_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='scriptinfo',
            name='status',
            field=models.BooleanField(default=True),
        ),
    ]
