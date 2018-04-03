#!/usr/bin/env python

from eiqjson import EIQEntity as types

MISPtoEIQtable={
                'md5':{'eiqtype':types.OBSERVABLE_MD5,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_MALWARE_ARTIFACTS,types.INDICATOR_FILE_HASH_WATCHLIST]},
                'sha1':{'eiqtype':types.OBSERVABLE_SHA1,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_MALWARE_ARTIFACTS,types.INDICATOR_FILE_HASH_WATCHLIST]},
                'sha256':{'eiqtype':types.OBSERVABLE_SHA256,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_MALWARE_ARTIFACTS,types.INDICATOR_FILE_HASH_WATCHLIST]},
                'sha512':{'eiqtype':types.OBSERVABLE_SHA512,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_MALWARE_ARTIFACTS,types.INDICATOR_FILE_HASH_WATCHLIST]},
                'filename':{'eiqtype':types.OBSERVABLE_FILE,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_MALWARE_ARTIFACTS,types.INDICATOR_FILE_HASH_WATCHLIST]},
                'pdb':{'eiqtype':types.OBSERVABLE_FILE,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_MALWARE_ARTIFACTS,types.INDICATOR_FILE_HASH_WATCHLIST]},
                'ip-src':{'eiqtype':types.OBSERVABLE_IPV4,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_IP_WATCHLIST]},
                'ip-dst':{'eiqtype':types.OBSERVABLE_IPV4,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_IP_WATCHLIST,types.INDICATOR_C2]},
                'port':{'eiqtype':types.OBSERVABLE_PORT,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_IP_WATCHLIST,types.INDICATOR_C2]},
                'hostname':{'eiqtype':types.OBSERVABLE_DOMAIN,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_DOMAIN_WATCHLIST]},
                'domain':{'eiqtype':types.OBSERVABLE_DOMAIN,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_DOMAIN_WATCHLIST]},
                'email-src':{'eiqtype':types.OBSERVABLE_EMAIL,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_MEDIUM,'indicator_types':[types.INDICATOR_MALICIOUS_EMAIL]},
                'email-dst':{'eiqtype':types.OBSERVABLE_EMAIL,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_LOW,'indicator_types':[types.INDICATOR_MALICIOUS_EMAIL]},
                'email-subject':{'eiqtype':types.OBSERVABLE_EMAIL_SUBJECT,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_MEDIUM,'indicator_types':[types.INDICATOR_MALICIOUS_EMAIL]},
                'uri':{'eiqtype':types.OBSERVABLE_URI,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_URL_WATCHLIST]},
                'url':{'eiqtype':types.OBSERVABLE_URI,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_URL_WATCHLIST]},
                'regkey':{'eiqtype':types.OBSERVABLE_WINREGISTRY,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_MALWARE_ARTIFACTS,types.INDICATOR_HOST_CHARACTERISTICS]},
                'as':{'eiqtype':types.OBSERVABLE_ASN,'classification':types.CLASSIFICATION_UNKNOWN},
                'snort':{'eiqtype':types.OBSERVABLE_SNORT,'classification':types.CLASSIFICATION_GOOD},
                'yara':{'eiqtype':types.OBSERVABLE_YARA,'classification':types.CLASSIFICATION_GOOD},
                'vulnerability':{'eiqtype':types.OBSERVABLE_CVE},
                'link':{'eiqtype':types.OBSERVABLE_URI,'classification':types.CLASSIFICATION_GOOD},
                'mutex':{'eiqtype':types.OBSERVABLE_MUTEX,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_MALWARE_ARTIFACTS]},
                'threat-actor':{'eiqtype':types.OBSERVABLE_ACTOR,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH},
                'x509-fingerprint-sha1':{'eiqtype':types.OBSERVABLE_SHA1,'classification':types.CLASSIFICATION_BAD,'confidence':types.CONFIDENCE_HIGH,'indicator_types':[types.INDICATOR_COMPROMISED_PKI_CERTIFICATE,types.INDICATOR_MALWARE_ARTIFACTS]},
                'org':{'eiqtype':types.OBSERVABLE_ORGANIZATION,'classification':types.CLASSIFICATION_GOOD},
                'orgc':{'eiqtype':types.OBSERVABLE_ORGANIZATION,'classification':types.CLASSIFICATION_GOOD},
}

TextToTTPtable={
                'banking':[types.TTP_ADVANTAGE,types.TTP_ADVANTAGE_ECONOMIC],
                'economic':[types.TTP_ADVANTAGE,types.TTP_ADVANTAGE_ECONOMIC],
                'fraud':[types.TTP_FRAUD,types.TTP_ADVANTAGE_ECONOMIC],
                'ransomware':[types.TTP_DISRUPTION,types.TTP_DESTRUCTION,types.TTP_EXTORTION],
                'intellectual property':[types.TTP_THEFT,types.TTP_THEFT_INTELLECTUAL_PROPERTY,types.TTP_THEFT_THEFT_OF_PROPRIETARY_INFORMATION],
                'proprietary information':[types.TTP_THEFT,types.TTP_THEFT_INTELLECTUAL_PROPERTY,types.TTP_THEFT_THEFT_OF_PROPRIETARY_INFORMATION],
                'brand damage':[types.TTP_BRAND_DAMAGE],
                'political':[types.TTP_ADVANTAGE_POLITICAL],
                'credential theft':[types.TTP_THEFT_CREDENTIAL_THEFT,types.TTP_THEFT],
                'identity theft':[types.TTP_THEFT_IDENTITY_THEFT,types.TTP_THEFT],
                'destruction':[types.TTP_DESTRUCTION],
                'disruption':[types.TTP_DISRUPTION],
                'traffic diversion':[types.TTP_TRAFFIC_DIVERSION],
                'extortion':[types.TTP_EXTORTION],
                'unauthorized access':[types.TTP_UNAUTHORIZED_ACCESS],
                'account takeover':[types.TTP_ACCOUNT_TAKEOVER],
                'harassment':[types.TTP_HARASSMENT],
}

OtherTypes=['comment','text']