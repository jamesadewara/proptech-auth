from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def send_html_email(subject: str, to_email: str, template_name: str, context: dict):
    """
    Sends an HTML email using Django templates.
    Automatically switches between console mode (dev) and SMTP (prod).
    """
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@proptech.com")
    
    try:
        html_content = render_to_string(template_name, context)
        text_content = render_to_string(template_name, context).replace("<br>", "\n").strip()

        msg = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
        msg.attach_alternative(html_content, "text/html")

        msg.send(fail_silently=False)
        logger.info(f"✅ Email sent to {to_email} - {subject}")

        return True
    except Exception as e:
        logger.error(f"❌ Failed to send email to {to_email}: {e}")
        return False
