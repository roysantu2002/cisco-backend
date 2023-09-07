# Generated by Django 4.2.4 on 2023-09-05 02:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scripts', '0004_networkdeviceinfo_status'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScriptInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('script_file', models.FileField(upload_to='scripts/')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_modified', models.DateTimeField(auto_now=True)),
                ('author', models.CharField(max_length=255)),
                ('version', models.CharField(max_length=50)),
                ('arguments', models.TextField()),
                ('execution_frequency', models.CharField(max_length=50)),
                ('status', models.CharField(choices=[('active', 'Active'), ('inactive', 'Inactive')], max_length=20)),
                ('info', models.TextField()),
            ],
        ),
    ]
