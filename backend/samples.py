"""
Preloaded Forensic Attack Datasets for SIH26106 Live Presentations
Includes:
1. PayPal Credential Harvester (Typosquatting + Failed DMARC + Bulletproof Relay)
2. CEO Fraud / Business Email Compromise (Display Name Spoofing + Urgent Wire Request)
3. SBI Banking KYC Suspension (Malicious Link + Phishing Lure)
4. Legitimate Verified Transaction (Google / GitHub Cloud Notification)
"""

SAMPLES = {
    "paypal_phishing": {
        "id": "paypal_phishing",
        "title": "🚨 PayPal Credential Harvester",
        "description": "Lookalike domain (paypa1-security.com), DMARC failure, and bulletproof relay in Russia/Germany.",
        "raw_email": """Delivered-To: victim@university.edu.in
Received: by 2002:a05:6512:128d:b0:4f2:91ab:d5e4 with SMTP id e4csp1287950;
        Tue, 2 Sep 2026 14:22:15 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of support@paypa1-security.com does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=support@paypa1-security.com;
       dkim=fail header.i=@paypa1-security.com;
       dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypa1-security.com
Received: from mail-relay.de.network ([194.26.29.112])
        by mx.google.com with ESMTPS id j12si45012plb.145.2026.09.02.14.22.14
        for <victim@university.edu.in>;
        Tue, 02 Sep 2026 14:22:14 -0700 (PDT)
Received: from bulletproof-mta.ru ([185.220.101.5])
        by mail-relay.de.network with ESMTP id mta99281;
        Tue, 02 Sep 2026 21:21:40 +0000
From: "PayPal Security Center" <support@paypa1-security.com>
To: <victim@university.edu.in>
Subject: URGENT: Unauthorized Access Detected - Confirm Your Identity Within 24 Hours
Date: Tue, 2 Sep 2026 21:21:30 +0000
Message-ID: <891238912.1287319@paypa1-security.com>
Reply-To: security-reply@paypa1-security.com
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Customer,

We detected an unauthorized login attempt to your PayPal account from an unrecognized IP address in Moscow, Russia.

Action Required: Your account will be permanently suspended unless you verify your identity within 24 hours.

Please click the secure link below to confirm your password and billing details:
https://paypa1-security.com/auth/login-verify.php

Failure to verify will result in forfeiture of your remaining balance.

Sincerely,
PayPal Fraud Prevention Team
"""
    },

    "ceo_fraud_bec": {
        "id": "ceo_fraud_bec",
        "title": "👔 CEO Fraud / Business Email Compromise",
        "description": "Executive display-name spoofing with artificial urgency and confidential bank routing request.",
        "raw_email": """Delivered-To: finance@techcorp.in
Received: by 2002:a17:902:d547:b0:1d2:8871:c109 with SMTP id x9csp491204;
        Wed, 3 Sep 2026 00:15:30 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=neutral (google.com: 45.142.214.88 is neither permitted nor denied by domain of executive-cloudnet.tk) smtp.mailfrom=director@executive-cloudnet.tk;
       dkim=neutral (no key for signature);
       dmarc=fail (p=NONE) header.from=executive-cloudnet.tk
Received: from mail-proxy.ams.nl ([45.142.214.88])
        by mx.google.com with ESMTPS id o18si89211wma.22.2026.09.03.00.15.29
        for <finance@techcorp.in>;
        Wed, 03 Sep 2026 00:15:29 -0700 (PDT)
Received: from mtn-client.ng ([102.89.44.18])
        by mail-proxy.ams.nl with ESMTP id nl0091;
        Wed, 03 Sep 2026 07:14:50 +0000
From: "Satya Nadella (Microsoft Office)" <director@executive-cloudnet.tk>
To: <finance@techcorp.in>
Subject: Urgent & Confidential: Acquisition Wire Transfer Instructions
Date: Wed, 3 Sep 2026 07:14:40 +0000
Message-ID: <bec-20260903001@executive-cloudnet.tk>
Reply-To: private-desk@executive-cloudnet.tk
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hi Finance Team,

I am currently in an urgent confidential meeting regarding our strategic corporate acquisition.

I need you to process an immediate wire transfer of INR 18,50,000 for vendor escrow deposit.
Due to strict non-disclosure obligations, do not call my office line or discuss this with anyone until closing.

Kindly confirm once you are at your desk so I can send over the beneficiary SWIFT transfer routing details immediately.

Regards,
Satya Nadella
Chief Executive Officer
"""
    },

    "sbi_kyc_phish": {
        "id": "sbi_kyc_phish",
        "title": "🏦 SBI Bank KYC Suspension Phishing",
        "description": "Indian banking lure targeting SBI customers with spoofed display name and credential link.",
        "raw_email": """Delivered-To: customer@gmail.com
Received: by 2002:a05:6512:128d:b0:4f2:91ab:d5e4 with SMTP id e4csp1287950;
        Tue, 2 Sep 2026 18:40:10 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of alerts@onlinesbi-portal.xyz does not designate 185.220.101.5 as permitted sender);
       dkim=fail;
       dmarc=fail (p=REJECT) header.from=onlinesbi-portal.xyz
Received: from relay-node.de ([194.26.29.112])
        by mx.google.com with ESMTPS id sbi10928;
        Tue, 02 Sep 2026 18:40:08 -0700 (PDT)
Received: from offshore-server.ru ([185.220.101.5])
        by relay-node.de with ESMTP id kyc9920;
        Tue, 02 Sep 2026 18:39:50 +0000
From: "State Bank of India Alert" <alerts@onlinesbi-portal.xyz>
To: <customer@gmail.com>
Subject: Mandatory SBI YONO KYC Update: Account Blocked in 24 Hours
Date: Tue, 2 Sep 2026 18:39:40 +0000
Message-ID: <sbi-kyc-alert-99120@onlinesbi-portal.xyz>
Content-Type: text/plain; charset=UTF-8

Dear Valued Customer,

Your State Bank of India (SBI) NetBanking account has been temporarily restricted due to non-compliance with RBI Mandatory KYC guidelines.

Immediate action required: If KYC is not completed, your ATM Card and UPI transactions will be blocked.

Click the official link below to submit your Aadhaar and PAN Card details:
https://onlinesbi-portal.xyz/yono/update-kyc.html

Do not share this link with anyone.
State Bank of India - Security Advisory Desk
"""
    },

    "legitimate_email": {
        "id": "legitimate_email",
        "title": "✅ Legitimate Google Cloud Notification",
        "description": "Authentic enterprise email with 100% verified SPF, DKIM, DMARC, and clean corporate relays.",
        "raw_email": """Delivered-To: developer@techcompany.com
Received: by 2002:a05:6512:128d:b0:4f2:91ab:d5e4 with SMTP id e4csp1287950;
        Tue, 2 Sep 2026 10:11:00 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of 3j7kd-noreply@google.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=3j7kd-noreply@google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X9Ak1L;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id j18sor9812901plb.14.2026.09.02.10.10.59
        for <developer@techcompany.com>;
        Tue, 02 Sep 2026 10:10:59 -0700 (PDT)
From: "Google Cloud Platform" <cloud-noreply@google.com>
To: <developer@techcompany.com>
Subject: Google Cloud: Scheduled Maintenance Window Notification
Date: Tue, 02 Sep 2026 10:10:58 -0700
Message-ID: <gcp-notify-20260902@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hello Google Cloud Developer,

This is a scheduled notification regarding upcoming system maintenance for Cloud SQL instances in the asia-south1 region.

Maintenance window: Saturday, Sep 5, 2026, 02:00 UTC - 03:00 UTC.
Expected impact: Minimal failover time (<60 seconds).

No action is required from your side. You can track status on the Google Cloud Console dashboard:
https://cloud.google.com/status

Thank you,
Google Cloud Operations Team
"""
    }
}
