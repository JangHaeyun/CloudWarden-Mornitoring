import json
import urllib.request

def lambda_handler(event, context):
    try:
        alarm_name = event['detail']['alarmName']
        new_state = event['detail']['state']['value']
        reason = event['detail'].get('state', {}).get('reason', 'No reason provided')

        message = (
            "**🚨 Alarm Triggered**\n"
            f"**Name**: {alarm_name}\n"
            f"**State**: {new_state}\n"
            f"**Reason**: {reason}"
        )

        webhook_url = "https://discordapp.com/api/webhooks/1398829441412763778/kpLVFm_4BFrIVT4lQ7asyPdeWYd0tYEloPUCICyQRM8aNtFd9OEtW_CHXHkoGlExhRBA"

        data = json.dumps({"content": message}).encode('utf-8')
        req = urllib.request.Request(webhook_url, data=data, headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0"
        })
        with urllib.request.urlopen(req) as response:
            response.read()

        return {
            'statusCode': 200,
            'body': json.dumps('Notification sent successfully')
        }

    except Exception as e:
        print(f"Error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Notification failed: {e}")
        }
