#!/usr/bin/env python3

### (c) 2018 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl> and Sebastiaan Groot
### <sebastiaang _monkeytail_ kpn-cert.nl> (for his EIQ lib)
### This software is GPLv3 licensed, except where otherwise indicated

import os
import sys
import json
import re
import optparse
import requests
import urllib3
import datetime
import eiqjson
import eiqcalls
import pprint

from MISPtoEIQtable import *
from config import settings

def mapAtrribute(mispEvent,entity):
    '''
    Attempt to parse all known observable types first. Treat all other attributes as 'comments' that go into
    the description field in EIQ, and set the TTP fields accordingly.
    '''
    if 'observable_types' in mispEvent:
        for observable in mispEvent['observable_types']:
            for type in observable:
                if type in MISPtoEIQtable:
                    if 'classification' in MISPtoEIQtable[type]:
                        classification=MISPtoEIQtable[type]['classification']
                    else:
                        classification=None
                    if 'confidence' in MISPtoEIQtable[type]:
                        confidence=MISPtoEIQtable[type]['confidence']
                    else:
                        confidence=None
                    entity.add_observable(MISPtoEIQtable[type]['eiqtype'],observable[type],classification=classification,confidence=confidence)
                    if 'indicator_types' in MISPtoEIQtable[type]:
                        for indicator_type in MISPtoEIQtable[type]['indicator_types']:
                            entity.add_indicator_type(indicator_type)
                else:
                    if type in OtherTypes:
                        entity.set_entity_description(entity.get_entity_description()+"<pre>"+type+": "+observable[type]+"</pre>")
                        if entity.get_entity_type() == entity.ENTITY_TTP:
                            for key in TextToTTPtable:
                                if key in observable[type]:
                                    for ttp_type in TextToTTPtable[key]:
                                        entity.add_ttp_type(ttp_type)
    return entity

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
            mispEvent=eventDict['Event']
            attributelist={'observable_types':[],'indicator_types':[],'ttp_types':[]}
            entity=eiqjson.EIQEntity()
            if options.type=='i':
                entity.set_entity(entity.ENTITY_INDICATOR)
            if options.type=='s':
                entity.set_entity(entity.ENTITY_SIGHTING)
            if options.type=='t':
                entity.set_entity(entity.ENTITY_TTP)
            entity.set_entity_source(settings.EIQSOURCE)
            if not 'info' in mispEvent:
                print("E) MISP Entity ID has no title, which can lead to problems ingesting, processing and finding data in EIQ.")
                sys.exit(1)
            entity.set_entity_title(settings.TITLETAG+" Event "+str(eventID)+" - "+mispEvent['info'])
            if 'timestamp' in mispEvent:
                timestamp=datetime.datetime.utcfromtimestamp(int(mispEvent['timestamp'])).strftime("%Y-%m-%dT%H:%M:%SZ")
            entity.set_entity_observed_time(timestamp)
            if 'uuid' in mispEvent:
                uuid=mispEvent['uuid']
            else:
                uuid=str(eventID)
            tlp=''
            for tag in mispEvent['Tag']:
                tagid=tag['id'].lower()
                tagname=tag['name'].lower()
                if tagname.startswith('tlp:') and not tlp:
                    tlp=tagname[4:]
                if tagname.startswith('misp-galaxy:threat-actor='):
                    attributelist['observable_types'].append({'threat-actor':re.sub('[\'\"\`]','',tag['name'][26:])})
                if tagname.startswith('admiralty-scale:source-reliability='):
                    entity.set_entity_reliability(re.sub('[\'\"\`]','',tag['name'][36:].upper()))
            if not tlp:
                tlp='amber'
            entity.set_entity_tlp(tlp)
            if options.type=='i' or options.type=='s':
                entity.set_entity_impact(options.impact)
            entity.set_entity_confidence(options.confidence)
            if 'Org' or 'Orgc' in mispEvent:
                attributelist['observable_types'].append({'org':mispEvent['Org']['name']})
            if 'Attribute' in mispEvent:
                for attribute in mispEvent['Attribute']:
                    type=attribute['type'].lower()
                    value=attribute['value']
                    if '|' in type:
                        type1,type2=type.split('|')
                        value1,value2=value.split('|')
                        attributelist['observable_types'].append({type1:value1})
                        attributelist['observable_types'].append({type2:value2})
                    else:
                        attributelist['observable_types'].append({type:value})
            if 'ShadowAttribute' in mispEvent:
                for attribute in mispEvent['ShadowAttribute']:
                    type=attribute['type'].lower()
                    value=attribute['value']
                    if '|' in type:
                        type1,type2=type.split('|')
                        value1,value2=value.split('|')
                        attributelist['observable_types'].append({type1:value1})
                        attributelist['observable_types'].append({type2:value2})
                    else:
                        attributelist['observable_types'].append({type:value})
            if 'Object' in mispEvent:
                for attribute in mispEvent['Object']:
                    if 'Attribute' in attribute:
                        for attribute in attribute['Attribute']:
                            type=attribute['type'].lower()
                            value=attribute['value']
                            if '|' in type:
                                type1,type2=type.split('|')
                                value1,value2=value.split('|')
                                attributelist['observable_types'].append({type1:value1})
                                attributelist['observable_types'].append({type2:value2})
                            else:
                                attributelist['observable_types'].append({type:value})
            return mapAtrribute(attributelist,entity).get_as_json(),uuid
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