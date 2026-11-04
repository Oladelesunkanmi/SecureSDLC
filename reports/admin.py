from django.contrib import admin
from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("project", "generated_by", "generated_at", "file")
    list_filter = ("generated_at",)

