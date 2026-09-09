from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0014_iocindicator'),
    ]

    operations = [
        migrations.AddField(
            model_name='iocindicator',
            name='source_model',
            field=models.CharField(blank=True, db_index=True, max_length=80),
        ),
        migrations.AddField(
            model_name='iocindicator',
            name='source_object_id',
            field=models.PositiveIntegerField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name='iocindicator',
            name='evidence_summary',
            field=models.CharField(blank=True, max_length=300),
        ),
        migrations.AddField(
            model_name='iocindicator',
            name='attack_phase',
            field=models.CharField(blank=True, db_index=True, max_length=40),
        ),
        migrations.AddField(
            model_name='iocindicator',
            name='asg_risk_score',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='iocindicator',
            name='asg_confidence',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.RemoveConstraint(
            model_name='iocindicator',
            name='uniq_ioc_session_type_value_source',
        ),
        migrations.AddConstraint(
            model_name='iocindicator',
            constraint=models.UniqueConstraint(fields=('session_id', 'ioc_type', 'ioc_value', 'source_event', 'source_model', 'source_object_id'), name='uniq_ioc_session_type_value_source'),
        ),
    ]