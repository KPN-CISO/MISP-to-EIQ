#!/usr/bin/env python3

# (c) 2018 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>
# and Sebastiaan Groot <sebastiaang _monkeytail_ kpn-cert.nl> (for his
# EIQ lib)

# This software is GPLv3 licensed, except where otherwise indicated

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
import socket
import copy

from MISPtoEIQtable import *
from config import settings


def mapAttribute(mispEvent, entity):
    '''
    Attempt to parse all known observable types first. Treat most other
    attributes as 'comments' that go into the description field in EIQ,
    and set the TTP fields accordingly.
    '''
    if 'observable_types' in mispEvent:
        for observable in mispEvent['observable_types']:
            for type in observable:
                if type in MISPtoEIQtable:
                    if 'classification' in MISPtoEIQtable[type]:
                        classification = MISPtoEIQtable[type]['classification']
                    else:
                        classification = None
                    if 'confidence' in MISPtoEIQtable[type]:
                        confidence = MISPtoEIQtable[type]['confidence']
                    else:
                        confidence = None
                    name, to_ids = observable[type]
                    eiqtype = MISPtoEIQtable[type]['eiqtype']
                    if to_ids or\
                       eiqtype == entity.OBSERVABLE_SNORT or\
                       eiqtype == entity.OBSERVABLE_YARA:
                        link_type = entity.OBSERVABLE_LINK_TEST_MECHANISM
                        classification = entity.CLASSIFICATION_BAD
                        confidence = entity.CONFIDENCE_HIGH
                    else:
                        link_type = entity.OBSERVABLE_LINK_OBSERVED
                    if eiqtype == types.OBSERVABLE_IPV4:
                        try:
                            socket.inet_aton(name)
                            eiqtype = types.OBSERVABLE_IPV4
                        except socket.error:
                            pass
                        try:
                            socket.inet_pton(socket.AF_INET6, name)
                            eiqtype = types.OBSERVABLE_IPV6
                        except socket.error:
                            pass
                    entity.add_observable(eiqtype,
                                          name,
                                          classification=classification,
                                          confidence=confidence,
                                          link_type=link_type)
                    if 'indicator_types' in MISPtoEIQtable[type]:
                        for itype in MISPtoEIQtable[type]['indicator_types']:
                            entity.add_indicator_type(itype)
                else:
                    if type in OtherTypes:
                        name, to_ids = observable[type]
                        entity.set_entity_description(
                            entity.get_entity_description() +
                            "<h2>-- " + type.upper() + " --</h2><p>" +
                            name + "</p>")
                        if entity.get_entity_type() == entity.ENTITY_TTP:
                            for key in TextToTTPtable:
                                if key in name:
                                    for ttp_type in TextToTTPtable[key]:
                                        entity.add_ttp_type(ttp_type)
    return entity


def transform(eventDict, eventID, options):
    '''
    Take the MISP Python Dictionary object, extract all attributes into a list,
    and pass that to the mapAttribute function for parsing. The resulting
    eiqJSON blob is sent to eiqIngest() for ingestion into EclecticIQ.
    '''
    if options.verbose:
        print("U) Converting Event into EIQ JSON ...")
    if options.confidence not in ('Unknown', 'None', 'Low', 'Medium', 'High'):
        print("E) Not a valid confidence setting! Please choose 'Unknown', " +
              "'None', 'Low', 'Medium' or 'High'.")
        sys.exit(1)
    if options.impact not in ('Unknown', 'None', 'Low', 'Medium', 'High'):
        print("E) Not a valid impact setting! Please choose 'Unknown', " +
              "'None', 'Low', 'Medium' or 'High'.")
        sys.exit(1)
    try:
        if 'Event' in eventDict:
            '''
            Create a list of entities to ingest into EclecticIQ. For a
            reasonably complete MISP Event, this means a TTP entity
            will be created, with an Actor entity and at least one
            Indicator entity linked to it.
            '''
            entityList = []
            entityTypeList = []
            '''
            First, create the central TTP Entity and add it to the list.
            '''
            mispEvent = eventDict['Event']
            attributelist = {'observable_types': [],
                             'indicator_types': [],
                             'ttp_types': []}
            entity = eiqjson.EIQEntity()
            if options.type == 'i':
                entity.set_entity(entity.ENTITY_INDICATOR)
            if options.type == 's':
                entity.set_entity(entity.ENTITY_SIGHTING)
            if options.type == 't':
                entity.set_entity(entity.ENTITY_TTP)
            entity.set_entity_source(settings.EIQSOURCE)
            if 'info' not in mispEvent:
                print("E) MISP Entity ID has no title, which can lead to " +
                      "problems ingesting, processing and finding data in " +
                      "EIQ.")
                sys.exit(1)
            else:
                info = mispEvent['info']
            if 'timestamp' in mispEvent:
                timestamp = datetime.datetime.utcfromtimestamp(
                    int(mispEvent['timestamp'])).strftime("%Y-%m-%dT%H:%M:%SZ")
            entity.set_entity_observed_time(timestamp)
            uuid = str(eventID) + '-MISP'
            tlp = ''
            actor = None
            reliability = 'F'
            if 'Tag' in mispEvent:
                for tag in mispEvent['Tag']:
                    tagname = tag['name'].lower()
                    if tagname.startswith('tlp:') and not tlp:
                        tlp = tagname[4:]
                    if tagname.startswith('misp-galaxy:threat-actor='):
                        actor = re.sub('[\'\"`]', '', tag['name'][26:])
                        attributelist['observable_types'].append(
                            {'threat-actor': (actor, False)})
                    if tagname.startswith(
                       'admiralty-scale:source-reliability='):
                        reliability = re.sub('[\'\"`]', '',
                                             tag['name'][36:].upper())
            if tlp not in ['white', 'green', 'amber', 'red']:
                tlp = 'amber'
            entity.set_entity_tlp(tlp)
            entity.set_entity_reliability(reliability)
            entity.set_entity_confidence(options.confidence)
            if 'Org' in mispEvent:
                org = mispEvent['Org']['name']
            if 'Orgc' in mispEvent:
                orgc = mispEvent['Orgc']['name']
                attributelist['observable_types'].append(
                    {'org': (orgc, False)}
                )
                orgcTag = '[' + orgc + ']'
            else:
                orgcTag = settings.TITLETAG
            entity.set_entity_title(info + " - MISP " +
                                    str(eventID) + " - " +
                                    orgcTag)
            entityList.append((mapAttribute(attributelist,
                               entity).get_as_json(), uuid))
            entityTypeList.append(entity.ENTITY_TTP)
            '''
            Check if there was an 'Actor' in the MISP Event and create/update
            the corresponding Actor entity in EclecticIQ
            '''
            if actor:
                entity = eiqjson.EIQEntity()
                entity.set_entity(entity.ENTITY_ACTOR)
                entity.add_actor_type(entity.ACTOR_TYPE_HACKER)
                entity.set_entity_tlp(tlp)
                entity.set_entity_confidence(options.confidence)
                entity.set_entity_source(settings.EIQSOURCE)
                entity.set_entity_observed_time(timestamp)
                entity.set_entity_title(actor + " - Threat Actor")
                uuid = actor + " - Threat Actor"
                attributelist = {'observable_types': [],
                                 'indicator_types': [],
                                 'ttp_types': []}
                if orgc:
                    attributelist['observable_types'].append(
                        {'org': (orgc, False)}
                    )
                attributelist['observable_types'].append(
                    {'threat-actor': (actor, False)})
                entityList.append((mapAttribute(attributelist,
                                   entity).get_as_json(), uuid))
                entityTypeList.append(entity.ENTITY_ACTOR)
            '''
            Now take the built-in attributes and create an Indicator entity
            for those MISP Attributes
            '''
            if 'Attribute' or 'ShadowAttribute' in mispEvent:
                attributelist = {'observable_types': [],
                                 'indicator_types': [],
                                 'ttp_types': []}
                entity = eiqjson.EIQEntity()
                entity.set_entity(entity.ENTITY_INDICATOR)
                if options.type == 'i' or options.type == 's':
                    entity.set_entity_impact(options.impact)
                entity.set_entity_source(settings.EIQSOURCE)
                entity.set_entity_observed_time(timestamp)
                entity.set_entity_tlp(tlp)
                if actor:
                    attributelist['observable_types'].append(
                        {'threat-actor': (actor, False)})
                if orgc:
                    attributelist['observable_types'].append(
                        {'org': (orgc, False)})
                entity.set_entity_reliability(reliability)
                if options.type == 'i' or options.type == 's':
                    entity.set_entity_impact(options.impact)
                entity.set_entity_confidence(options.confidence)
                typeslist = []
                attributeslist = []
                if 'Attribute' in mispEvent:
                    attributeslist += mispEvent['Attribute']
                if 'ShadowAttribute' in mispEvent:
                    attributeslist += mispEvent['ShadowAttribute']
                for attribute in attributelist:
                    if 'Attribute' in attribute:
                        attributes += attribute['attribute']
                for attribute in attributeslist:
                    if 'to_ids' in attribute:
                        to_ids = attribute['to_ids']
                    else:
                        to_ids = False
                    type = attribute['type'].lower()
                    value = attribute['value']
                    if type == 'threat-actor':
                        actor = value
                        actorentity = eiqjson.EIQEntity()
                        actorentity.set_entity(actorentity.ENTITY_ACTOR)
                        actorentity.add_actor_type(actorentity.ACTOR_TYPE_HACKER)
                        actorentity.set_entity_tlp(tlp)
                        actorentity.set_entity_confidence(options.confidence)
                        actorentity.set_entity_source(settings.EIQSOURCE)
                        actorentity.set_entity_observed_time(timestamp)
                        actorentity.set_entity_title(actor + " - Threat Actor")
                        uuid = actor + " - Threat Actor"
                        actorlist = {'observable_types': [],
                                     'indicator_types': [],
                                     'ttp_types': []}
                        actorlist['observable_types'].append(
                            {'threat-actor': (actor, False)})
                        entityList.append((mapAttribute(actorlist,
                                           actorentity).get_as_json(), uuid))
                        entityTypeList.append(actorentity.ENTITY_ACTOR)
                    if '|' in type:
                        type1, type2 = type.split('|')
                        typeslist.append(type1)
                        typeslist.append(type2)
                        try:
                            value1, value2 = value.split('|')
                            attributelist['observable_types'].append(
                                {type1: (value1, to_ids)}
                            )
                            attributelist['observable_types'].append(
                                {type2: (value2, to_ids)}
                            )
                        except ValueError:
                            value1 = value.replace('|','')
                            attributelist['observable_types'].append(
                                {type1: (value1, to_ids)}
                            )
                    else:
                        typeslist.append(type)
                        attributelist['observable_types'].append(
                            {type: (value, to_ids)}
                        )
                types = ", ".join(set(typeslist))
                if len(types) > (settings.TITLELENGTH + 4):
                    types = types[:settings.TITLELENGTH] + " ..."
                uuid = str(eventID) + '-0-MISP'
                title = info + " - Main IoCs: "
                #title += str(len(typeslist)) + " - "
                title += types
                title += " - MISP "
                title += str(eventID)
                title += " - " + orgcTag
                entity.set_entity_title(title)
                entityList.append((mapAttribute(attributelist,
                                                entity).get_as_json(), uuid))
                entityTypeList.append(entity.ENTITY_INDICATOR)
            '''
            Now take all the MISP Objects and add them to the list of
            entities for EIQ
            '''
            if 'Object' in mispEvent:
                for attribute in mispEvent['Object']:
                    '''
                    Create an EIQ Entity for set of Attributes belonging
                    to a MISP Object
                    '''
                    attributelist = {'observable_types': [],
                                     'indicator_types': [],
                                     'ttp_types': []}
                    entity = eiqjson.EIQEntity()
                    entity.set_entity(entity.ENTITY_INDICATOR)
                    if options.type == 'i' or options.type == 's':
                        entity.set_entity_impact(options.impact)
                    entity.set_entity_source(settings.EIQSOURCE)
                    if 'description' not in attribute:
                        print("E) MISP Entity ID has no title, which can " +
                              "lead to problems ingesting, processing and " +
                              "finding data in EclecticIQ.")
                        sys.exit(1)
                    entity.set_entity_observed_time(timestamp)
                    uuid = str(eventID) + '-' + attribute['id'] + '-MISP'
                    entity.set_entity_tlp(tlp)
                    if actor:
                        attributelist['observable_types'].append(
                            {'threat-actor': (actor, False)})
                    if orgc:
                        attributelist['observable_types'].append(
                            {'org': (orgc, False)})
                    entity.set_entity_reliability(reliability)
                    if options.type == 'i' or options.type == 's':
                        entity.set_entity_impact(options.impact)
                    entity.set_entity_confidence(options.confidence)
                    typeslist = []
                    if 'Attribute' in attribute:
                        for attribute in attribute['Attribute']:
                            if 'to_ids' in attribute:
                                to_ids = attribute['to_ids']
                            else:
                                to_ids = False
                            type = attribute['type'].lower()
                            value = attribute['value']
                            if type == 'threat-actor':
                                actor = value
                                actorentity = eiqjson.EIQEntity()
                                actorentity.set_entity(actorentity.ENTITY_ACTOR)
                                actorentity.add_actor_type(actorentity.ACTOR_TYPE_HACKER)
                                actorentity.set_entity_tlp(tlp)
                                actorentity.set_entity_confidence(options.confidence)
                                actorentity.set_entity_source(settings.EIQSOURCE)
                                actorentity.set_entity_observed_time(timestamp)
                                actorentity.set_entity_title(actor + " - Threat Actor")
                                uuid = actor + " - Threat Actor"
                                attributelist = {'observable_types': [],
                                                 'indicator_types': [],
                                                 'ttp_types': []}
                                attributelist['observable_types'].append(
                                    {'threat-actor': (actor, False)})
                                entityList.append((mapAttribute(attributelist,
                                                   actorentity).get_as_json(),
                                                   uuid))
                                entityTypeList.append(actorentity.ENTITY_ACTOR)
                            if '|' in type:
                                type1, type2 = type.split('|')
                                typeslist.append(type1)
                                typeslist.append(type2)
                                value1, value2 = value.split('|')
                                attributelist['observable_types'].append(
                                    {type1: (value1, to_ids)}
                                )
                                attributelist['observable_types'].append(
                                    {type2: (value2, to_ids)}
                                )
                            else:
                                typeslist.append(type)
                                attributelist['observable_types'].append(
                                    {type: (value, to_ids)}
                                )
                    types = ", ".join(set(typeslist))
                    if len(types) > (settings.TITLELENGTH + 4):
                        types = types[:settings.TITLELENGTH] + " ..."
                    title = info + " - Add. IoCs: "
                    #title += str(len(typeslist)) + " - "
                    title += types
                    title += " - MISP "
                    title += str(eventID)
                    title += " - " + orgcTag
                    entity.set_entity_title(title)
                    if len(typeslist) > 0:
                        print("---START---")
                        print(mapAttribute(attributelist,entity).get_as_json())
                        print("----END----")
                        entityList.append((mapAttribute(attributelist,
                                                        entity).get_as_json(),
                                           uuid))
                        entityTypeList.append(entity.ENTITY_INDICATOR)
            return entityList, entityTypeList
            if not options.verbose:
                print("E) An empty result or other error was returned by " +
                      "MISP. Enable verbosity to see the JSON result that " +
                      "was returned.")
            else:
                print("E) An empty JSON result or other error was returned " +
                      "by MISP:")
                print(eventDict)
    except KeyError:
        raise


def eiqIngest(eiqJSON, options, uuid):
    '''
    Ingest the provided eiqJSON object into EIQ with the UUID provided
    (or create a new entity if not previously existing)
    '''
    if options.simulate:
        if options.verbose:
            print("U) Not ingesting anything into EIQ because the " +
                  "-s/--simulate flag was set.")
        return False

    if not settings.EIQSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for EIQ, " +
                  "this is not recommended.")

    eiqAPI = eiqcalls.EIQApi(insecure=not(settings.EIQSSLVERIFY))
    url = settings.EIQHOST + settings.EIQVERSION
    eiqAPI.set_host(url)
    eiqAPI.set_credentials(settings.EIQUSER, settings.EIQPASS)
    token = eiqAPI.do_auth()
    try:
        if options.verbose:
            print("U) Contacting " + url + ' to ingest ' + uuid + ' ...')
        if not options.duplicate:
            response = eiqAPI.create_entity(eiqJSON, token=token,
                                            update_identifier=uuid)
        else:
            response = eiqAPI.create_entity(eiqJSON, token=token)
    except IOError:
        raise
    if not response or ('errors' in response):
        if response:
            for err in response['errors']:
                print('[error %d] %s' % (err['status'], err['title']))
                print('\t%s' % (err['detail'], ))
        else:
            print('unable to get a response from host')
        return False
    else:
        return response['data']['id']


def create_relation(sourceuuid, sourcetype, targetuuid, targettype,
                    options, uuid):
    if options.simulate:
        if options.verbose:
            print("U) Not ingesting anything into EIQ because the " +
                  "-s/--simulate flag was set.")
        return False

    if not settings.EIQSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for EIQ, " +
                  "this is not recommended.")

    relation = eiqjson.EIQRelation()
    if sourcetype == eiqjson.EIQEntity.ENTITY_ACTOR:
        relation.set_relation(relation.RELATION_ACTOR_TTP,
                              label=relation.LABEL_ASSOCIATED_CAMPAIGN)
        relation.set_source(sourceuuid, eiqjson.EIQEntity.ENTITY_ACTOR)
        relation.set_target(targetuuid, eiqjson.EIQEntity.ENTITY_TTP)
    if sourcetype == eiqjson.EIQEntity.ENTITY_INDICATOR:
        relation.set_relation(relation.RELATION_INDICATOR_TTP,
                              label=relation.LABEL_ASSOCIATED_CAMPAIGN)
        relation.set_source(sourceuuid, eiqjson.EIQEntity.ENTITY_INDICATOR)
        relation.set_target(targetuuid, eiqjson.EIQEntity.ENTITY_TTP)
    relation.set_ingest_source(settings.EIQSOURCE)
    new_options = copy.copy(options)
    new_options.duplicate = True
    eiqIngest(relation.get_as_json(), new_options, uuid)


def download(eventID, options):
    '''
    Download the given MISP Event number from MISP
    '''
    if options.verbose:
        print("U) Parsing MISP Event ID " + str(eventID) + " ...")
    try:
        eventurl = settings.MISPURL+"/events/" + str(eventID)
        apiheaders = {
            "Accept": "application/json",
            "Content-type": "application/json",
            "Authorization": settings.MISPTOKEN
        }
        if not settings.MISPSSLVERIFY:
            if options.verbose:
                print("W) You have disabled SSL verification for MISP, " +
                      "this is not recommended!")
            urllib3.disable_warnings()
        if options.verbose:
            print("U) Contacting " + eventurl + " ...")
        response = requests.get(
            eventurl,
            headers=apiheaders,
            verify=settings.MISPSSLVERIFY
        )
        mispdict = response.json()
        if options.verbose:
            print("U) Got a MISP response:")
            pprint.pprint(mispdict)
        return mispdict
    except IOError:
        if options.verbose:
            print("E) An error occured downloading MISP Event ID " +
                  eventID +
                  " from " +
                  settings.MISPURL)
        raise
        sys.exit(1)


if __name__ == "__main__":
    cli = optparse.OptionParser(usage="usage: %prog [-v | -c | -i | -t | -s " +
                                      "| -n | -d] <MISP Event ID>")
    cli.add_option('-v', '--verbose',
                   dest='verbose',
                   action='store_true',
                   default=False,
                   help='[optional] Enable progress/error info (default: ' +
                        'disabled)')
    cli.add_option('-c', '--confidence',
                   dest='confidence',
                   default='Unknown',
                   help='[optional] Set the confidence level for the ' +
                        'EclecticIQ entity (default: \'Unknown\')')
    cli.add_option('-i', '--impact',
                   dest='impact',
                   default='Unknown',
                   help='[optional] Set the impact level for the EclecticIQ ' +
                        'entity (default: \'Unknown\')')
    cli.add_option('-t', '--type',
                   dest='type',
                   default='t',
                   help='[optional] Set the type of EclecticIQ entity you ' +
                        'wish to create: [t]tp (default), [s]ighting ' +
                        'or [i]ndicator. Not all entity types support all ' +
                        'observables/extracts! Nested objects in the MISP ' +
                        'Event will be created as indicators and linked to ' +
                        'the TTP.')
    cli.add_option('-s', '--simulate',
                   dest='simulate',
                   action='store_true',
                   default=False,
                   help='[optional] Do not actually ingest anything into ' +
                        'EIQ, just simulate everything. Mostly useful with ' +
                        'the -v/--verbose flag.')
    cli.add_option('-n', '--name',
                   dest='name',
                   default=settings.TITLETAG,
                   help='[optional] Override the default TITLETAG name from ' +
                        'the configuration file (default: TITLETAG in' +
                        'settings.py)')
    cli.add_option('-d', '--duplicate',
                   dest='duplicate',
                   action='store_true',
                   default=False,
                   help='[optional] Do not update the existing EclecticIQ ' +
                        'entity, but create a new one (default: disabled)')
    (options, args) = cli.parse_args()
    if options.confidence not in ('Unknown', 'None', 'Low', 'Medium', 'High'):
        print("E) Not a valid confidence setting! Please choose 'Unknown', " +
              "'None', 'Low', 'Medium' or 'High'.")
        sys.exit(1)
    if options.impact not in ('Unknown', 'None', 'Low', 'Medium', 'High'):
        print("E) Not a valid impact setting! Please choose 'Unknown',' " +
              "'None', 'Low', 'Medium' or 'High'.")
        sys.exit(1)
    if len(args) < 1:
        cli.print_help()
        sys.exit(1)
    if len(args) > 1:
        print("E) Please specify exactly one EventID only.")
        sys.exit(1)
    else:
        try:
            eventID = int(args[0])
        except:
            print("E) Please specify a numeric EventID only.")
            sys.exit(1)
        eventDict = download(eventID, options)
        if 'message' in eventDict:
            print("E) An error occurred, MISP returned: " +
                  eventDict['message'])
            sys.exit(1)
        else:
            entities, entitytypes = transform(eventDict, eventID, options)
            if entities:
                relations = []
                for i in range(0, len(entities)):
                    eiqJSON, uuid = entities[i]
                    if options.verbose:
                        print(json.dumps(json.loads(eiqJSON),
                                         indent=2,
                                         sort_keys=True))
                    eiquuid = eiqIngest(eiqJSON, options, uuid)
                    entitytype = entitytypes[i]
                    if entitytype == eiqjson.EIQEntity.ENTITY_TTP:
                        ttpuuid = eiquuid
                    if entitytype == eiqjson.EIQEntity.ENTITY_ACTOR:
                        create_relation(eiquuid, entitytype, ttpuuid,
                                        eiqjson.EIQEntity.ENTITY_TTP,
                                        options, uuid)
                    if entitytype == eiqjson.EIQEntity.ENTITY_INDICATOR:
                        create_relation(eiquuid, entitytype, ttpuuid,
                                        eiqjson.EIQEntity.ENTITY_TTP,
                                        options, uuid)
