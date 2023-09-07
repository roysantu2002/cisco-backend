from django.db import models

STATUS_CHOICES = (
    ('active', 'Active'),
    ('inactive', 'Inactive'),
    # Add more choices as needed
)

class ScriptInfo(models.Model):
    name = models.CharField(max_length=255, unique=True)  # Name of the script
    description = models.TextField(blank=True, null=True)  # Description of the script (optional)
    script_file = models.FileField(upload_to='scripts/', blank=True)  # Store the script file
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for when the record was created
    last_modified = models.DateTimeField(auto_now=True)  # Timestamp for when the record was last modified
    author = models.CharField(max_length=255)  # Author of the script
    version = models.CharField(max_length=50, blank=True)  # Version number of the script
    arguments = models.TextField(blank=True)  # Arguments required by the script
    execution_frequency = models.CharField(max_length=50, blank=True)  # How often the script runs
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)  # Script status (e.g., active, inactive)
    info = models.TextField(blank=True)


    def __str__(self):
        return self.name

class NetworkDeviceInfo(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    host_name = models.CharField(max_length=255)
    status = models.BooleanField(default=True)
    info = models.TextField()

    def __str__(self):
        return f"{self.host_name} ({self.ip_address})"


class NetworkDeviceLog(models.Model):
    device = models.ForeignKey(NetworkDeviceInfo, on_delete=models.CASCADE)
    log_data = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Log for {self.device.host_name} ({self.device.ip_address})"
