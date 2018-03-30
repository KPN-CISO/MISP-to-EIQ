#!/usr/bin/env python3

### (c) 2018 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl> and Sebastiaan Groot
### <sebastiaang _monkeytail_ kpn-cert.nl> (for his EIQ lib)
### This software is GPLv3 licensed, except where otherwise indicated

import os, sys, json, re, optparse, requests, urllib3, datetime, eiqjson, eiqcalls, pprint
from config import settings

def eiqIngest(eiqJSON,options,uuid):
    if not settings.EIQSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for EIQ, this is not recommended.")
    eiqAPI=eiqcalls.EIQApi(insecure=not(settings.EIQSSLVERIFY))
    eiqAPI.set_host(settings.EIQURL)
    eiqAPI.set_credentials(settings.EIQUSER,settings.EIQPASS)
    token = eiqAPI.do_auth()
    if not options.simulate:
        try:
            if options.verbose:
                print("U) Contacting "+settings.EIQURL+' ...')
            if not options.duplicate:
                response=eiqAPI.create_entity(eiqJSON,token=token,update_identifier=uuid)
            else:
                response=eiqAPI.create_entity(eiqJSON,token=token)
        except:
            raise
            print("E) An error occurred contacting the EIQ URL at "+settings.EIQURL)
        if not response or 'errors' in response:
            if response:
                for err in response['errors']:
                    print('[error %d] %s' % (err['status'], err['title']))
                    print('\t%s' % (err['detail'],))
            else:
                print('unable to get a response from host')
    else:
        if options.verbose:
            print("U) Not ingesting anything into EIQ because the -s/--simulate flag was set.")

def transform(eventDict,eventID,options):
    if options.verbose:
        print("U) Converting Event into EIQ JSON ...")
    if not options.confidence in ('Unknown','None','Low','Medium','High'):
        print("E) Not a valid confidence setting! Please choose 'Unknown', 'None', 'Low', 'Medium' or 'High'.")
        sys.exit(1)
    if not options.impact in ('Unknown','None','Low','Medium','High'):
        print("E) Not a valid impact setting! Please choose 'Unknown', 'None', 'Low', 'Medium' or 'High'.")
        sys.exit(1)
    try:
        if 'Event' in eventDict:
            mispevent=eventDict['Event']
            entity=eiqjson.EIQEntity()
            if options.type=='i':
                entity.set_entity(entity.ENTITY_INDICATOR)
            if options.type=='s':
                entity.set_entity(entity.ENTITY_SIGHTING)
            if options.type=='t':
                entity.set_entity(entity.ENTITY_TTP)
            entity.set_entity_source(settings.EIQSOURCE)
            if not 'info' in mispevent:
                print("E) MISP Entity ID has no title, which can lead to problems ingesting, processing and finding data in EIQ.")
                sys.exit(1)
            entity.set_entity_title(settings.TITLETAG+" Event "+str(eventID)+" - "+mispevent['info'])
            if 'timestamp' in mispevent:
                timestamp=datetime.datetime.utcfromtimestamp(int(mispevent['timestamp'])).strftime("%Y-%m-%dT%H:%M:%SZ")
            entity.set_entity_observed_time(timestamp)
            if 'uuid' in mispevent:
                uuid=mispevent['uuid']
            else:
                uuid=str(eventID)
            if 'Org' in mispevent:
                entity.add_observable(entity.OBSERVABLE_ORGANIZATION,mispevent['Org']['name'],classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_HIGH)
            if 'Orgc' in mispevent:
                entity.add_observable(entity.OBSERVABLE_ORGANIZATION,mispevent['Orgc']['name'],classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_HIGH)
            tlp=''
            for tag in mispevent['Tag']:
                tagid=tag['id'].lower()
                tagname=tag['name'].lower()
                if tagname.startswith('tlp:') and not tlp:
                    tlp=tagname[4:]
                if tagname.startswith('misp-galaxy:threat-actor='):
                    entity.add_observable(entity.OBSERVABLE_ACTOR,re.sub('[\'\"\`]','',tag['name'][26:]))
                if tagname.startswith('admiralty-scale:source-reliability='):
                    entity.set_entity_reliability(re.sub('[\'\"\`]','',tag['name'][36:].upper()))
            if not tlp:
                tlp='amber'
            entity.set_entity_tlp(tlp)
            if options.type=='i' or options.type=='s':
                entity.set_entity_impact(options.impact)
            entity.set_entity_confidence(options.confidence)
            if 'ShadowAttribute' in mispevent:
                for attribute in mispevent['ShadowAttribute']:
                    if 'Org' in attribute:
                        entity.add_observable(entity.OBSERVABLE_ORGANIZATION,attribute['Org']['name'],classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_HIGH)
                    if 'Orgc' in attribute:
                        entity.add_observable(entity.OBSERVABLE_ORGANIZATION,attribute['Orgc']['name'],classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_HIGH)
                    category=attribute['category'].lower()
                    type=attribute['type'].lower()
                    value=attribute['value']
                    if category=='antivirus detection':
                        if type=='url' or type=='link':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_LOW)
                    if category=='artifacts dropped':
                        if type.startswith('filename|'):
                            filename=value.split('|')[0]
                            value=value.split('|')[1]
                            type=type.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_FILE,filename,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='mutex':
                            entity.add_observable(entity.OBSERVABLE_MUTEX,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='md5':
                            entity.add_observable(entity.OBSERVABLE_MD5,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha1':
                            entity.add_observable(entity.OBSERVABLE_SHA1,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha256':
                            entity.add_observable(entity.OBSERVABLE_SHA256,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha512':
                            entity.add_observable(entity.OBSERVABLE_SHA512,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='email-subject':
                            entity.add_observable(entity.OBSERVABLE_EMAIL_SUBJECT,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='email-body':
                            entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='email-src':
                            entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='filename':
                            entity.add_observable(entity.OBSERVABLE_FILE,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='url':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='snort':
                            entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                        if type=='yara':
                            entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                    if category=='attribution':
                        if type=='comment':
                            entity.set_entity_description(entity.get_entity_description()+"<pre>"+value+"</pre>")
                    if category=='payload delivery' or category=='payload installation':
                        if type.startswith('filename|'):
                            filename=value.split('|')[0]
                            value=value.split('|')[1]
                            type=type.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_FILE,filename,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='domain' or type=='hostname':
                            entity.add_observable(entity.OBSERVABLE_DOMAIN,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='mutex':
                            entity.add_observable(entity.OBSERVABLE_MUTEX,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='md5':
                            entity.add_observable(entity.OBSERVABLE_MD5,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha1':
                            entity.add_observable(entity.OBSERVABLE_SHA1,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha256':
                            entity.add_observable(entity.OBSERVABLE_SHA256,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha512':
                            entity.add_observable(entity.OBSERVABLE_SHA512,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='email-subject':
                            entity.add_observable(entity.OBSERVABLE_EMAIL_SUBJECT,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='email-body':
                            entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='email-src':
                            entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='filename':
                            entity.add_observable(entity.OBSERVABLE_FILE,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='url':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='snort':
                            entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                        if type=='yara':
                            entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                    if category=='persistence mechanism':
                        if type=='regkey':
                            entity.add_observable(entity.OBSERVABLE_WINREGISTRY,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if category=='external analysis':
                        if type.startswith('filename|'):
                            filename=value.split('|')[0]
                            value=value.split('|')[1]
                            type=type.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_FILE,filename,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='link':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_LOW)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='url':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_LOW)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='mutex':
                            entity.add_observable(entity.OBSERVABLE_MUTEX,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='md5':
                            entity.add_observable(entity.OBSERVABLE_MD5,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha1':
                            entity.add_observable(entity.OBSERVABLE_SHA1,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha256':
                            entity.add_observable(entity.OBSERVABLE_SHA256,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha512':
                            entity.add_observable(entity.OBSERVABLE_SHA512,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='filename':
                            entity.add_observable(entity.OBSERVABLE_FILE,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='comment':
                            if attribute['comment']:
                                comment=attribute['comment']
                                entity.set_entity_description(entity.get_entity_description()+"<pre>Comment: "+comment+" - "+value+"</pre>")
                            else:
                                entity.set_entity_description(entity.get_entity_description()+"<pre>Comment: "+value+"</pre>")                                
                        if type=='snort':
                            entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                        if type=='yara':
                            entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                        if type=='text':
                            entity.set_entity_description(entity.get_entity_description()+"<pre>"+value+"</pre>")
                    if category=='network activity':
                        if type=='domain' or type=='hostname':
                            entity.add_observable(entity.OBSERVABLE_DOMAIN,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type.startswith('domain|ip'):
                            domain=value.split('|')[0]
                            ip=value.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_DOMAIN,domain,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            entity.add_observable(entity.OBSERVABLE_IPV4,ip,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if type=='ip-src':
                            entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='ip-dst':
                            entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='url':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='snort':
                            entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                        if type=='yara':
                            entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                    if category=='other':
                        entity.set_entity_description(entity.get_entity_description()+"<pre>"+value+"</pre>")
                        analysis=value.lower()
                        if 'banking' in analysis:
                            entity.add_ttp_type(entity.TTP_ADVANTAGE)
                            entity.add_ttp_type(entity.TTP_ADVANTAGE_ECONOMIC)
                        if 'fraud' in analysis:
                            entity.add_ttp_type(entity.TTP_FRAUD)
                        if ('intellectual property' or 'proprietary information') in analysis:
                            entity.add_ttp_type(entity.TTP_THEFT)
                            entity.add_ttp_type(entity.TTP_THEFT_INTELLECTUAL_PROPERTY)
                            entity.add_ttp_type(entity.TTP_THEFT_THEFT_OF_PROPRIETARY_INFORMATION)
                        if 'brand damage' in analysis:
                            entity.add_ttp_type(entity.TTP_BRAND_DAMAGE)
                        if 'political' in analysis:
                            entity.add_ttp_type(entity.TTP_ADVANTAGE_POLITICAL)
                        if 'theft' in analysis:
                            entity.add_ttp_type(entity.TTP_THEFT)
                            if 'credential theft' in analysis:
                                entity.add_ttp_type(entity.TTP_THEFT_CREDENTIAL_THEFT)
                            if 'identity theft' in analysis:
                                entity.add_ttp_type(entity.TTP_THEFT_IDENTITY_THEFT)
                        if 'economic' in analysis:
                            entity.add_ttp_type(entity.TTP_ADVANTAGE)
                            entity.add_ttp_type(entity.TTP_ADVANTAGE_ECONOMIC)
                        if 'destruction' in analysis:
                            entity.add_ttp_type(entity.TTP_DESTRUCTION)
                        if 'disruption' in analysis:
                            entity.add_ttp_type(entity.TTP_DISRUPTION)
                        if 'traffic diversion' in analysis:
                            entity.add_ttp_type(entity.TTP_TRAFFIC_DIVERSION)
                        if 'extortion' in analysis:
                            entity.add_ttp_type(entity.TTP_EXTORTION)
                        if 'unauthorized access' in analysis:
                            entity.add_ttp_type(entity.TTP_UNAUTHORIZED_ACCESS)
                        if 'account takeover' in analysis:
                            entity.add_ttp_type(entity.TTP_ACCOUNT_TAKEOVER)
                        if 'harassment' in analysis:
                            entity.add_ttp_type(entity.TTP_HARASSMENT)
            attributes=mispevent['Attribute']
            for attribute in mispevent['Attribute']:
                category=attribute['category'].lower()
                type=attribute['type'].lower()
                value=attribute['value']
                if category=='antivirus detection':
                    if type=='url' or type=='link':
                        entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_LOW)
                if category=='artifacts dropped':
                    if type.startswith('filename|'):
                        filename=value.split('|')[0]
                        value=value.split('|')[1]
                        type=type.split('|')[1]
                        entity.add_observable(entity.OBSERVABLE_FILE,filename,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if type.startswith('domain|ip'):
                        domain=value.split('|')[0]
                        ip=value.split('|')[1]
                        entity.add_observable(entity.OBSERVABLE_DOMAIN,domain,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        entity.add_observable(entity.OBSERVABLE_IPV4,ip,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                    if type=='mutex':
                        entity.add_observable(entity.OBSERVABLE_MUTEX,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if type=='md5':
                        entity.add_observable(entity.OBSERVABLE_MD5,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha1':
                        entity.add_observable(entity.OBSERVABLE_SHA1,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha256':
                        entity.add_observable(entity.OBSERVABLE_SHA256,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha512':
                        entity.add_observable(entity.OBSERVABLE_SHA512,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='email-subject':
                        entity.add_observable(entity.OBSERVABLE_EMAIL_SUBJECT,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                    if type=='email-body':
                        entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                    if type=='email-src':
                        entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                    if type=='filename':
                        entity.add_observable(entity.OBSERVABLE_FILE,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if type=='url':
                        entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                    if type=='snort':
                        entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                    if type=='yara':
                        entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                if category=='attribution':
                    if type=='comment':
                        entity.set_entity_description(entity.get_entity_description()+"<pre>"+value+"</pre>")
                if category=='payload delivery' or category=='payload installation':
                    if type.startswith('filename|'):
                        filename=value.split('|')[0]
                        value=value.split('|')[1]
                        type=type.split('|')[1]
                        entity.add_observable(entity.OBSERVABLE_FILE,filename,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if type.startswith('domain|ip'):
                        domain=value.split('|')[0]
                        ip=value.split('|')[1]
                        entity.add_observable(entity.OBSERVABLE_DOMAIN,domain,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        entity.add_observable(entity.OBSERVABLE_IPV4,ip,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                            entity.add_indicator_type(entity.INDICATOR_C2)
                    if type=='domain' or type=='hostname':
                        entity.add_observable(entity.OBSERVABLE_DOMAIN,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                            entity.add_indicator_type(entity.INDICATOR_C2)
                    if type=='vulnerability':
                        entity.add_observable(entity.OBSERVABLE_CVE,value)
                    if type=='mutex':
                        entity.add_observable(entity.OBSERVABLE_MUTEX,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if type=='md5':
                        entity.add_observable(entity.OBSERVABLE_MD5,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha1':
                        entity.add_observable(entity.OBSERVABLE_SHA1,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha256':
                        entity.add_observable(entity.OBSERVABLE_SHA256,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha512':
                        entity.add_observable(entity.OBSERVABLE_SHA512,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='email-subject':
                        entity.add_observable(entity.OBSERVABLE_EMAIL_SUBJECT,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                    if type=='email-body':
                        entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                    if type=='email-src':
                        entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                    if type=='filename':
                        entity.add_observable(entity.OBSERVABLE_FILE,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if type=='url':
                        entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                    if type=='ip-src':
                        entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                            entity.add_indicator_type(entity.INDICATOR_C2)
                    if type=='ip-dst':
                        entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                            entity.add_indicator_type(entity.INDICATOR_C2)
                    if type=='snort':
                        entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                    if type=='yara':
                        entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                if category=='persistence mechanism':
                    if type=='regkey':
                        entity.add_observable(entity.OBSERVABLE_WINREGISTRY,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                if category=='external analysis':
                    if type.startswith('filename|'):
                        filename=value.split('|')[0]
                        value=value.split('|')[1]
                        type=type.split('|')[1]
                        entity.add_observable(entity.OBSERVABLE_FILE,filename,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if type.startswith('domain|ip'):
                        domain=value.split('|')[0]
                        ip=value.split('|')[1]
                        entity.add_observable(entity.OBSERVABLE_DOMAIN,domain,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        entity.add_observable(entity.OBSERVABLE_IPV4,ip,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                            entity.add_indicator_type(entity.INDICATOR_C2)
                    if type=='link':
                        entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                    if type=='url':
                        entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                    if type=='mutex':
                        entity.add_observable(entity.OBSERVABLE_MUTEX,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if type=='md5':
                        entity.add_observable(entity.OBSERVABLE_MD5,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha1':
                        entity.add_observable(entity.OBSERVABLE_SHA1,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha256':
                        entity.add_observable(entity.OBSERVABLE_SHA256,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha512':
                        entity.add_observable(entity.OBSERVABLE_SHA512,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='filename':
                        entity.add_observable(entity.OBSERVABLE_FILE,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if type=='comment':
                        if attribute['comment']:
                            comment=attribute['comment']
                            entity.set_entity_description(entity.get_entity_description()+"<pre>Comment: "+comment+" - "+value+"</pre>")
                        else:
                            entity.set_entity_description(entity.get_entity_description()+"<pre>Comment: "+value+"</pre>")                                
                    if type=='snort':
                        entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                    if type=='yara':
                        entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                    if type=='text':
                        entity.set_entity_description(entity.get_entity_description()+"<pre>"+value+"</pre>")
                if category=='network activity':
                    if type.startswith('domain|ip'):
                        domain=value.split('|')[0]
                        ip=value.split('|')[1]
                        entity.add_observable(entity.OBSERVABLE_DOMAIN,domain,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        entity.add_observable(entity.OBSERVABLE_IPV4,ip,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                            entity.add_indicator_type(entity.INDICATOR_C2)
                    if type=='domain' or type=='hostname':
                        entity.add_observable(entity.OBSERVABLE_DOMAIN,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                            entity.add_indicator_type(entity.INDICATOR_C2)
                    if type=='ip-src':
                        entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                            entity.add_indicator_type(entity.INDICATOR_C2)
                    if type=='ip-dst':
                        entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                            entity.add_indicator_type(entity.INDICATOR_C2)
                    if type=='url':
                        entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                        if options.type=='i':
                            entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                    if type=='snort':
                        entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                    if type=='yara':
                        entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                if category=='other':
                    entity.set_entity_description(entity.get_entity_description()+"<pre>"+value+"</pre>")
                    analysis=value.lower()
                    if 'banking' in analysis:
                        entity.add_ttp_type(entity.TTP_ADVANTAGE)
                        entity.add_ttp_type(entity.TTP_ADVANTAGE_ECONOMIC)
                    if 'fraud' in analysis:
                        entity.add_ttp_type(entity.TTP_FRAUD)
                    if ('intellectual property' or 'proprietary information') in analysis:
                        entity.add_ttp_type(entity.TTP_THEFT)
                        entity.add_ttp_type(entity.TTP_THEFT_INTELLECTUAL_PROPERTY)
                        entity.add_ttp_type(entity.TTP_THEFT_THEFT_OF_PROPRIETARY_INFORMATION)
                    if 'brand damage' in analysis:
                        entity.add_ttp_type(entity.TTP_BRAND_DAMAGE)
                    if 'political' in analysis:
                        entity.add_ttp_type(entity.TTP_ADVANTAGE_POLITICAL)
                    if 'theft' in analysis:
                        entity.add_ttp_type(entity.TTP_THEFT)
                        if 'credential theft' in analysis:
                            entity.add_ttp_type(entity.TTP_THEFT_CREDENTIAL_THEFT)
                        if 'identity theft' in analysis:
                            entity.add_ttp_type(entity.TTP_THEFT_IDENTITY_THEFT)
                    if 'economic' in analysis:
                        entity.add_ttp_type(entity.TTP_ADVANTAGE)
                        entity.add_ttp_type(entity.TTP_ADVANTAGE_ECONOMIC)
                    if 'destruction' in analysis:
                        entity.add_ttp_type(entity.TTP_DESTRUCTION)
                    if 'disruption' in analysis:
                        entity.add_ttp_type(entity.TTP_DISRUPTION)
                    if 'traffic diversion' in analysis:
                        entity.add_ttp_type(entity.TTP_TRAFFIC_DIVERSION)
                    if 'extortion' in analysis:
                        entity.add_ttp_type(entity.TTP_EXTORTION)
                    if 'unauthorized access' in analysis:
                        entity.add_ttp_type(entity.TTP_UNAUTHORIZED_ACCESS)
                    if 'account takeover' in analysis:
                        entity.add_ttp_type(entity.TTP_ACCOUNT_TAKEOVER)
                    if 'harassment' in analysis:
                        entity.add_ttp_type(entity.TTP_HARASSMENT)
            for attribute in mispevent['Object']:
                for shadowAttribute in attribute['Attribute']:
                    category=shadowAttribute['category'].lower()
                    type=shadowAttribute['type'].lower()
                    value=shadowAttribute['value']
                    if 'category' in shadowAttribute and shadowAttribute['category'].lower()=='other':
                        if 'malicious' in shadowAttribute['category']:
                            classification=entity.CLASSIFICATION_BAD
                            confidence=entity.CONFIDENCE_HIGH
                        else:
                            classification=''
                            confidence=''
                    if category=='antivirus detection':
                        if type=='url' or type=='link':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_HIGH)
                    if category=='artifacts dropped':
                        if type.startswith('filename|'):
                            filename=value.split('|')[0]
                            value=value.split('|')[1]
                            type=type.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_FILE,filename,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type.startswith('domain|ip'):
                            domain=value.split('|')[0]
                            ip=value.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_DOMAIN,domain,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            entity.add_observable(entity.OBSERVABLE_IPV4,ip,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='mutex':
                            entity.add_observable(entity.OBSERVABLE_MUTEX,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='md5':
                            entity.add_observable(entity.OBSERVABLE_MD5,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha1':
                            entity.add_observable(entity.OBSERVABLE_SHA1,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha256':
                            entity.add_observable(entity.OBSERVABLE_SHA256,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha512':
                            entity.add_observable(entity.OBSERVABLE_SHA512,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='email-subject':
                            entity.add_observable(entity.OBSERVABLE_EMAIL_SUBJECT,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='email-body':
                            entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='email-src':
                            entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='filename':
                            entity.add_observable(entity.OBSERVABLE_FILE,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='url':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='snort':
                            entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                        if type=='yara':
                            entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                    if category=='attribution':
                        if type=='comment':
                            entity.set_entity_description(entity.get_entity_description()+"<pre>"+value+"</pre>")
                    if category=='payload delivery' or category=='payload installation':
                        if type.startswith('filename|'):
                            filename=value.split('|')[0]
                            value=value.split('|')[1]
                            type=type.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_FILE,filename,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type.startswith('domain|ip'):
                            domain=value.split('|')[0]
                            ip=value.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_DOMAIN,domain,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            entity.add_observable(entity.OBSERVABLE_IPV4,ip,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='domain' or type=='hostname':
                            entity.add_observable(entity.OBSERVABLE_DOMAIN,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='mutex':
                            entity.add_observable(entity.OBSERVABLE_MUTEX,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='md5':
                            entity.add_observable(entity.OBSERVABLE_MD5,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha1':
                            entity.add_observable(entity.OBSERVABLE_SHA1,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha256':
                            entity.add_observable(entity.OBSERVABLE_SHA256,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha512':
                            entity.add_observable(entity.OBSERVABLE_SHA512,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='email-subject':
                            entity.add_observable(entity.OBSERVABLE_EMAIL_SUBJECT,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='email-body':
                            entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='email-src':
                            entity.add_observable(entity.OBSERVABLE_EMAIL,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALICIOUS_EMAIL)
                        if type=='filename':
                            entity.add_observable(entity.OBSERVABLE_FILE,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='url':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='ip-src':
                            entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='ip-dst':
                            entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='snort':
                            entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                        if type=='yara':
                            entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                    if category=='persistence mechanism':
                        if type=='regkey':
                            entity.add_observable(entity.OBSERVABLE_WINREGISTRY,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                    if category=='external analysis':
                        if type.startswith('filename|'):
                            filename=value.split('|')[0]
                            value=value.split('|')[1]
                            type=type.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_FILE,filename,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type.startswith('domain|ip'):
                            domain=value.split('|')[0]
                            ip=value.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_DOMAIN,domain,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            entity.add_observable(entity.OBSERVABLE_IPV4,ip,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='link':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='url':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_GOOD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='mutex':
                            entity.add_observable(entity.OBSERVABLE_MUTEX,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='md5':
                            entity.add_observable(entity.OBSERVABLE_MD5,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha1':
                            entity.add_observable(entity.OBSERVABLE_SHA1,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha256':
                            entity.add_observable(entity.OBSERVABLE_SHA256,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='sha512':
                            entity.add_observable(entity.OBSERVABLE_SHA512,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_FILE_HASH_WATCHLIST)
                        if type=='filename':
                            entity.add_observable(entity.OBSERVABLE_FILE,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_MALWARE_ARTIFACTS)
                        if type=='comment':
                            if shadowAttribute['comment']:
                                comment=shadowAttribute['comment']
                                entity.set_entity_description(entity.get_entity_description()+"<pre>Comment: "+comment+" - "+value+"</pre>")
                            else:
                                entity.set_entity_description(entity.get_entity_description()+"<pre>Comment: "+value+"</pre>")                                
                        if type=='snort':
                            entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                        if type=='yara':
                            entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                        if type=='text':
                            entity.set_entity_description(entity.get_entity_description()+"<pre>"+value+"</pre>")
                    if category=='network activity':
                        if type.startswith('domain|ip'):
                            domain=value.split('|')[0]
                            ip=value.split('|')[1]
                            entity.add_observable(entity.OBSERVABLE_DOMAIN,domain,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            entity.add_observable(entity.OBSERVABLE_IPV4,ip,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='domain' or type=='hostname':
                            entity.add_observable(entity.OBSERVABLE_DOMAIN,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_DOMAIN_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='ip-src':
                            entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='ip-dst':
                            entity.add_observable(entity.OBSERVABLE_IPV4,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_IP_WATCHLIST)
                                entity.add_indicator_type(entity.INDICATOR_C2)
                        if type=='url':
                            entity.add_observable(entity.OBSERVABLE_URI,value,classification=entity.CLASSIFICATION_BAD,confidence=entity.CONFIDENCE_HIGH)
                            if options.type=='i':
                                entity.add_indicator_type(entity.INDICATOR_URL_WATCHLIST)
                        if type=='snort':
                            entity.add_test_mechanism(entity.OBSERVABLE_SNORT,value)
                        if type=='yara':
                            entity.add_test_mechanism(entity.OBSERVABLE_YARA,value)
                    if category=='other':
                        analysis=value.lower()
                        if type=='comment':
                            entity.set_entity_description(entity.get_entity_description()+"<pre>"+value+"</pre>")
                        if 'banking' in analysis:
                            entity.add_ttp_type(entity.TTP_ADVANTAGE)
                            entity.add_ttp_type(entity.TTP_ADVANTAGE_ECONOMIC)
                        if 'fraud' in analysis:
                            entity.add_ttp_type(entity.TTP_FRAUD)
                        if ('intellectual property' or 'proprietary information') in analysis:
                            entity.add_ttp_type(entity.TTP_THEFT)
                            entity.add_ttp_type(entity.TTP_THEFT_INTELLECTUAL_PROPERTY)
                            entity.add_ttp_type(entity.TTP_THEFT_THEFT_OF_PROPRIETARY_INFORMATION)
                        if 'brand damage' in analysis:
                            entity.add_ttp_type(entity.TTP_BRAND_DAMAGE)
                        if 'political' in analysis:
                            entity.add_ttp_type(entity.TTP_ADVANTAGE_POLITICAL)
                        if 'theft' in analysis:
                            entity.add_ttp_type(entity.TTP_THEFT)
                            if 'credential theft' in analysis:
                                entity.add_ttp_type(entity.TTP_THEFT_CREDENTIAL_THEFT)
                            if 'identity theft' in analysis:
                                entity.add_ttp_type(entity.TTP_THEFT_IDENTITY_THEFT)
                        if 'economic' in analysis:
                            entity.add_ttp_type(entity.TTP_ADVANTAGE)
                            entity.add_ttp_type(entity.TTP_ADVANTAGE_ECONOMIC)
                        if 'destruction' in analysis:
                            entity.add_ttp_type(entity.TTP_DESTRUCTION)
                        if 'disruption' in analysis:
                            entity.add_ttp_type(entity.TTP_DISRUPTION)
                        if 'traffic diversion' in analysis:
                            entity.add_ttp_type(entity.TTP_TRAFFIC_DIVERSION)
                        if 'extortion' in analysis:
                            entity.add_ttp_type(entity.TTP_EXTORTION)
                        if 'unauthorized access' in analysis:
                            entity.add_ttp_type(entity.TTP_UNAUTHORIZED_ACCESS)
                        if 'account takeover' in analysis:
                            entity.add_ttp_type(entity.TTP_ACCOUNT_TAKEOVER)
                        if 'harassment' in analysis:
                            entity.add_ttp_type(entity.TTP_HARASSMENT)
            entity.set_entity_description(entity.get_entity_description()+"<pre>Original MISP UUID: "+uuid+"</pre>")
            return entity.get_as_json(),uuid
        else:
            if not options.verbose:
                print("E) An empty result or other error was returned by MISP. Enable verbosity to see the JSON result that was returned.")
            else:
                print("E) An empty JSON result or other error was returned by MISP:")
                print(eventDict)
    except:
        raise
        sys.exit(1)

def download(eventID,options):
    if options.verbose:
        print("U) Parsing MISP Event ID "+str(eventID)+" ...")
    try:
        eventurl=settings.MISPURL+"/events/"+str(eventID)
        apiheaders={
            "Accept":"application/json",
            "Content-type":"application/json",
            "Authorization":settings.MISPTOKEN
        }
        if not settings.MISPSSLVERIFY:
            if options.verbose:
                print("W) You have disabled SSL verification for MISP, this is not recommended.")
            urllib3.disable_warnings()
        if options.verbose:
            print("U) Contacting "+eventurl+" ...")
        response=requests.get(eventurl,headers=apiheaders,verify=settings.MISPSSLVERIFY)
        mispdict=response.json()
        if options.verbose:
            print("U) Got a MISP response:")
            pprint.pprint(mispdict)
        return mispdict
    except:
        if options.verbose:
            print("E) An error occured downloading MISP Event ID "+eventID+" from "+settings.MISPURL)
        raise
        sys.exit(1)

if __name__ == "__main__":
    cli=optparse.OptionParser(usage="usage: %prog [-q] <MISP Event ID>")
    cli.add_option('-v','--verbose',dest='verbose',action='store_true',default=False,help='[optional] Enable progress/error info (default: disabled)')
    cli.add_option('-c','--confidence',dest='confidence',default='Unknown',help='[optional] Set the confidence level for the EclecticIQ entity (default: \'Unknown\')')
    cli.add_option('-i','--impact',dest='impact',default='Unknown',help='[optional] Set the impact level for the EclecticIQ entity (default: \'Unknown\')')
    cli.add_option('-t','--type',dest='type',default='i',help='[optional] Set the type of EclecticIQ entity you wish to create: [i]ndicator (default), [s]ighting or [t]TP. Not all entity types support all observables/extracts!')
    cli.add_option('-s','--simulate',dest='simulate',action='store_true',default=False,help='[optional] Do not actually ingest anything into EIQ, just simulate everything. Mostly useful with the -v/--verbose flag.')
    cli.add_option('-n','--name',dest='name',default=settings.TITLETAG,help='[optional] Override the default TITLETAG name from the configuration file (default: TITLETAG in settings.py)')
    cli.add_option('-d','--duplicate',dest='duplicate',action='store_true',default=False,help='[optional] Do not update the existing EclecticIQ entity, but create a new one (default: disabled)')
    (options,args)=cli.parse_args()
    if not options.confidence in ('Unknown','None','Low','Medium','High'):
        print("E) Not a valid confidence setting! Please choose 'Unknown', 'None', 'Low', 'Medium' or 'High'.")
        sys.exit(1)
    if not options.impact in ('Unknown','None','Low','Medium','High'):
        print("E) Not a valid impact setting! Please choose 'Unknown', 'None', 'Low', 'Medium' or 'High'.")
        sys.exit(1)
    if len(args)<1:
        cli.print_help()
        sys.exit(1)
    if len(args)>1:
        print("E) Please specify exactly one EventID only.")
        sys.exit(1)
    else:
        try:
            eventID=int(args[0])
        except:
            print("E) Please specify a numeric EventID only.")
            sys.exit(1)
        eventDict=download(eventID,options)
        eiqJSON,uuid=transform(eventDict,eventID,options)
        if eiqJSON:
            if options.verbose:
                print(json.dumps(json.loads(eiqJSON),indent=2,sort_keys=True))
            eiqIngest(eiqJSON,options,uuid)