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

def transform(eventDict,eventID):
    if options.verbose:
        print("U) Converting Event into EIQ JSON ...")
    try:
        if 'Event' in eventDict:
            mispevent=eventDict['Event']
            sighting=eiqjson.EIQEntity()
            sighting.set_entity(sighting.ENTITY_INDICATOR)
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
            for attribute in mispevent['Attribute']:
                category=attribute['category'].lower()
                type=attribute['type'].lower()
                value=attribute['value']
                if category=='payload delivery' or category=='payload installation':
                    if type.startswith('filename|'):
                        filename=type[:9]
                        type=type[10:]
                        sighting.add_observable(sighting.OBSERVABLE_FILE,filename)
                    if type=='md5':
                        sighting.add_observable(sighting.OBSERVABLE_MD5,value)
                    if type=='sha1':
                        sighting.add_observable(sighting.OBSERVABLE_SHA1,value)
                    if type=='sha256':
                        sighting.add_observable(sighting.OBSERVABLE_SHA256,value)
                    if type=='sha512':
                        sighting.add_observable(sighting.OBSERVABLE_SHA512,value)
                    if type=='email-subject':
                        sighting.add_observable(sighting.OBSERVABLE_EMAIL_SUBJECT,value)
                    if type=='email-body':
                        sighting.add_observable(sighting.OBSERVABLE_EMAIL,value)
                    if type=='filename':
                        sighting.add_observable(sighting.OBSERVABLE_FILE,value)
                if category=='external analysis':
                    if type.startswith('filename|'):
                        filename=type[:9]
                        type=type[10:]
                        sighting.add_observable(sighting.OBSERVABLE_FILE,filename)
                    if type=='link':
                        sighting.add_observable(sighting.OBSERVABLE_URI,value)
                    if type=='md5':
                        sighting.add_observable(sighting.OBSERVABLE_MD5,value)
                    if type=='sha1':
                        sighting.add_observable(sighting.OBSERVABLE_SHA1,value)
                    if type=='sha256':
                        sighting.add_observable(sighting.OBSERVABLE_SHA256,value)
                    if type=='sha512':
                        sighting.add_observable(sighting.OBSERVABLE_SHA512,value)
                    if type=='filename':
                        sighting.add_observable(sighting.OBSERVABLE_FILE,value)
                if category=='network activity':
                    if type=='domain' or type=='hostname':
                        sighting.add_observable(sighting.OBSERVABLE_DOMAIN,value)
                    if type=='ip-dst':
                        sighting.add_observable(sighting.OBSERVABLE_IPV4,value)
                    if type=='url':
                        sighting.add_observable(sighting.OBSERVABLE_URI,value)
            return sighting.get_as_json()
    except:
        raise
        sys.exit(1)

def download(eventID):
    if options.verbose:
        print("U) Parsing MISP Event ID "+str(eventID)+" ...")
    try:
        eventurl=settings.MISPURL+"/events/"+eventID
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
    (options,args)=cli.parse_args()
    if len(args)<1:
        cli.print_help()
        sys.exit(1)
    if len(args)>1:
        if options.verbose:
            print("E) One EventID only, please.")
        sys.exit(1)
    else:
        eventID=args[0]
        eventDict=download(eventID)
        eiqJSON=transform(eventDict,eventID)
        if eiqJSON:
            print(eiqJSON)
            eiqIngest(eiqJSON)