# Generated by Django 4.2.4 on 2023-09-04 01:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scripts', '0003_networkdevicelog'),
    ]

    operations = [
        migrations.AddField(
            model_name='networkdeviceinfo',
            name='status',
            field=models.BooleanField(default=True),
        ),
    ]
