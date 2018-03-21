#!/usr/bin/env python3

### (c) 2018 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl> and Sebastiaan Groot
### <sebastiaang _monkeytail_ kpn-cert.nl> (for his EIQ lib)
### This software is GPLv3 licensed, except where otherwise indicated

import os, sys, json, re, optparse, requests, urllib3, datetime, eiqjson, eiqcalls
from config import settings

def eiqIngest(eiqJSON):
    if not settings.EIQSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for EIQ, this is not recommended.")
    eiqAPI=eiqcalls.EIQApi(insecure=not(settings.EIQSSLVERIFY))
    eiqAPI.set_host(settings.EIQURL+'/api')
    eiqAPI.set_credentials(settings.EIQUSER,settings.EIQPASS)
    try:
        response=eiqAPI.create_entity(eiqJSON)
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

def transform(eventDict,eventID,options):
    if options.verbose:
        print("U) Converting Event into EIQ JSON ...")
    try:
        if 'Event' in eventDict:
            mispevent=eventDict['Event']
            sighting=eiqjson.EIQEntity()
            if options.type=='i':
                sighting.set_entity(sighting.ENTITY_INDICATOR)
            if options.type=='s':
                sighting.set_entity(sighting.ENTITY_SIGHTING)
            sighting.set_entity_source(settings.EIQSOURCE)
            if not 'info' in mispevent:
                print("E) MISP Entity ID has no title, which can lead to problems ingesting, processing and finding data in EIQ.")
                sys.exit(1)
            sighting.set_entity_title(settings.TITLETAG+" Event "+str(eventID)+" - "+mispevent['info'])
            if 'value' in mispevent:
                sighting.set_entity_description(mispevent['value'])
            if 'timestamp' in mispevent:
                timestamp=datetime.datetime.utcfromtimestamp(int(mispevent['timestamp'])).strftime("%Y-%m-%dT%H:%M:%SZ")
            sighting.set_entity_observed_time(timestamp)
            tlp=''
            for tag in mispevent['Tag']:
                tagid=tag['id'].lower()
                tagname=tag['name'].lower()
                if tagname.startswith('tlp:') and not tlp:
                    tlp=(tagname[4:])
            if not tlp:
                tlp='amber'
            sighting.set_entity_tlp(tlp)
            sighting.set_entity_impact(options.impact)
            sighting.set_entity_confidence(options.confidence)
            for attribute in mispevent['Attribute']:
                category=attribute['category'].lower()
                type=attribute['type'].lower()
                value=attribute['value']
                if category=='payload delivery' or category=='payload installation':
                    if type.startswith('filename|'):
                        filename=type[:9]
                        type=type[10:]
                        sighting.add_observable(sighting.OBSERVABLE_FILE,filename)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_MALWARE_ARTIFACTS)
                    if type=='md5':
                        sighting.add_observable(sighting.OBSERVABLE_MD5,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha1':
                        sighting.add_observable(sighting.OBSERVABLE_SHA1,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha256':
                        sighting.add_observable(sighting.OBSERVABLE_SHA256,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha512':
                        sighting.add_observable(sighting.OBSERVABLE_SHA512,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='email-subject':
                        sighting.add_observable(sighting.OBSERVABLE_EMAIL_SUBJECT,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_MALICIOUS_EMAIL)
                    if type=='email-body':
                        sighting.add_observable(sighting.OBSERVABLE_EMAIL,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_MALICIOUS_EMAIL)
                    if type=='filename':
                        sighting.add_observable(sighting.OBSERVABLE_FILE,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_MALWARE_ARTIFACTS)
                if category=='external analysis':
                    if type.startswith('filename|'):
                        filename=type[:9]
                        type=type[10:]
                        sighting.add_observable(sighting.OBSERVABLE_FILE,filename)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_MALWARE_ARTIFACTS)
                    if type=='link':
                        sighting.add_observable(sighting.OBSERVABLE_URI,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.OBSERVABLE_URI)
                    if type=='md5':
                        sighting.add_observable(sighting.OBSERVABLE_MD5,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha1':
                        sighting.add_observable(sighting.OBSERVABLE_SHA1,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha256':
                        sighting.add_observable(sighting.OBSERVABLE_SHA256,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='sha512':
                        sighting.add_observable(sighting.OBSERVABLE_SHA512,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_FILE_HASH_WATCHLIST)
                    if type=='filename':
                        sighting.add_observable(sighting.OBSERVABLE_FILE,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_MALWARE_ARTIFACTS)
                if category=='network activity':
                    if type=='domain' or type=='hostname':
                        sighting.add_observable(sighting.OBSERVABLE_DOMAIN,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_DOMAIN_WATCHLIST)
                            sighting.add_indicator_type(sighting.INDICATOR_C2)
                    if type=='ip-dst':
                        sighting.add_observable(sighting.OBSERVABLE_IPV4,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_IP_WATCHLIST)
                            sighting.add_indicator_type(sighting.INDICATOR_C2)
                    if type=='url':
                        sighting.add_observable(sighting.OBSERVABLE_URI,value)
                        if options.type=='i':
                            sighting.add_indicator_type(sighting.INDICATOR_URL_WATCHLIST)
            return sighting.get_as_json()
        else:
            if not options.verbose:
                print("E) An empty result or other error was returned by MISP. Enable verbosity to see the JSON result that was returned.")
            else:
                print("E) An empty JSON result or other error was returned by MISP:")
                print(eventDict)
    except:
        raise
        sys.exit(1)

def download(eventID):
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
        response=requests.get(eventurl,headers=apiheaders,verify=settings.MISPSSLVERIFY)
        mispdict=response.json()
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
    cli.add_option('-t','--type',dest='type',default='i',help='[optional] Set the type of EclecticIQ entity you wish to create: [i]ndicator (default), [s]ighting. Not all entity types can be created, and not all entity types support all observables/extracts.')
    (options,args)=cli.parse_args()
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
        eventDict=download(eventID)
        eiqJSON=transform(eventDict,eventID,options)
        if eiqJSON:
            if options.verbose:
                print(eiqJSON)
            eiqIngest(eiqJSON)