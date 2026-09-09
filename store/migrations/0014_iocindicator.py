from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0013_attackjourney_risk_confidence_intent'),
    ]

    operations = [
        migrations.CreateModel(
            name='IOCIndicator',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_id', models.CharField(blank=True, db_index=True, max_length=80)),
                ('ioc_type', models.CharField(choices=[('ip', 'IP Address'), ('url', 'URL'), ('email', 'Email'), ('hash', 'Hash')], db_index=True, max_length=20)),
                ('ioc_value', models.CharField(db_index=True, max_length=512)),
                ('confidence_score', models.FloatField(default=0.0)),
                ('source_event', models.CharField(blank=True, db_index=True, max_length=80)),
                ('first_seen', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('last_seen', models.DateTimeField(auto_now=True, db_index=True)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('attack_journey', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='iocs', to='store.attackjourney')),
            ],
            options={
                'ordering': ['-last_seen'],
            },
        ),
        migrations.AddConstraint(
            model_name='iocindicator',
            constraint=models.UniqueConstraint(fields=('session_id', 'ioc_type', 'ioc_value', 'source_event'), name='uniq_ioc_session_type_value_source'),
        ),
    ]