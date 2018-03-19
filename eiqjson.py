#!/usr/bin/env python3

import json, time, uuid

"""EIQJson
A simple EIQ json generator

Example usage:
  obj = EIQJson()

  obj.set_entity(obj.ENTITY_SIGHTING, 'Entity Title', 'This sighting came from <...>', '2017-12-15T10:15:00+01:00')

  obj.add_observable(obj.OBSERVABLE_IPV4, '8.8.8.8')
  obj.add_observable(obj.OBSERVABLE_DOMAIN, 'dns.google.com')
  obj.add_observable(obj.OBSERVABLE_URI, 'https://dns.google.com/test.php')
  obj.add_observable(obj.OBSERVABLE_EMAIL, 'dns@google.com')

  with open('EntityTitle.json', 'w') as f:
    f.write(obj.get_as_json())
"""
class EIQEntity:
  ENTITY_INDICATOR = 'indicator'
  ENTITY_SIGHTING = 'eclecticiq-sighting'
  ENTITY_REPORT = 'report'
  ENTITY_TYPES = [
    ENTITY_INDICATOR,
    ENTITY_SIGHTING,
    ENTITY_REPORT
  ]

  OBSERVABLE_ACTOR = 'actor-id'
  OBSERVABLE_ADDRESS = 'address'
  OBSERVABLE_ASN = 'asn'
  OBSERVABLE_BANK_ACCOUNT = 'bank-account'
  OBSERVABLE_CARD = 'card'
  OBSERVABLE_CARD_OWNER = 'card-owner'
  OBSERVABLE_CCE = 'cce'
  OBSERVABLE_CITY = 'city'
  OBSERVABLE_COMPANY = 'company'
  OBSERVABLE_COUNTRY = 'country'
  OBSERVABLE_COUNTRY_CODE = 'country-code'
  OBSERVABLE_CVE = 'cve'

  OBSERVABLE_IPV4 = 'ipv4'
  OBSERVABLE_URI = 'uri'
  OBSERVABLE_DOMAIN = 'domain'
  OBSERVABLE_EMAIL = 'email'

  OBSERVABLE_MD5 = 'hash-md5'
  OBSERVABLE_SHA1 = 'hash-sha1'
  OBSERVABLE_SHA256 = 'hash-sha256'
  OBSERVABLE_SHA512 = 'hash-sha512'
  OBSERVABLE_FILE = 'file'
  OBSERVABLE_DOMAIN = 'domain'
  OBSERVABLE_EMAIL = 'email'
  OBSERVABLE_EMAIL_SUBJECT = 'email-subject'
  OBSERVABLE_WINREGISTRY = 'winregistry'

  OBSERVABLE_TYPES = [
    OBSERVABLE_IPV4,
    OBSERVABLE_URI,
    OBSERVABLE_DOMAIN,
    OBSERVABLE_EMAIL
  ]

  def __init__(self):
    self.__is_entity_set = False
    self.__doc = {}

  def set_entity(self, entity_type, entity_title = '', entity_description = '', observed_time = '', source = ''):
    if not entity_type in self.ENTITY_TYPES:
      raise Exception('Expecting entity_type from ENTITY_TYPES')

    self.__is_entity_set  = True

    entity = {}
    entity['data'] = {}
    entity['data']['type'] = entity_type
    entity['data']['title'] = entity_title
    entity['data']['description'] = entity_description

    entity['meta'] = {}
    entity['meta']['tlp_color'] = 'RED'
    entity['meta']['tags'] = []
    entity['meta']['estimated_observed_time'] = observed_time
    entity['meta']['half_life'] = 182 # EIQ default of half a year
    entity['meta']['source'] = source

    entity['platform-version'] = "2.0.1"
    entity['content-type'] = "urn:eclecticiq.com:json:1.0"


    self.__doc['data'] = entity

  def set_entity_source(self, source):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['meta']['source'] = source

  def set_entity_title(self, title):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['data']['title'] = title

  def set_entity_description(self, description):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['data']['description'] = description

  def set_entity_observed_time(self, observed_time):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['meta']['estimated_observed_time'] = observed_time

  def set_entity_reliability(self, reliability):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['meta']['source_reliability'] = reliability

  def set_entity_tlp(self, tlp):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['meta']['tlp_color'] = tlp.upper()

  def add_observable(self, observable_type, value):
#    if not observable_type in self.OBSERVABLE_TYPES:
#      raise Exception('Expecting observable_type from OBSERVABLE_TYPES')
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')

    if not 'bundled_extracts' in self.__doc['data']['meta'].keys():
      self.__doc['data']['meta']['bundled_extracts'] = []
      self.__doc['data']['meta']['bundled_extracts_only'] = True

    observable = {}
    
    observable['value'] = value
    observable['level'] = 2
    observable['kind'] = observable_type

    self.__doc['data']['meta']['bundled_extracts'].append(observable)

  def get_as_dict(self):
    return self.__doc

  def get_as_json(self):
    return json.dumps(self.__doc)

class EIQRelation:
  RELATION_REGULAR = 'REGULAR'
  RELATION_STIX_UPDATE = 'stix_update_of'
  RELATION_TYPES = [
    RELATION_REGULAR,
    RELATION_STIX_UPDATE
  ]
  
  def __init__(self):
    self.__is_relation_set = False
    self.__doc = {}

  def set_relation(self, relation_subtype, source_id = None, source_type = None, target_id = None, target_type = None):
    if not relation_subtype in self.RELATION_TYPES:
      raise Exception('Expecting relation_subtype from RELATION_TYPES')

    self.__is_relation_set = True
    self.__doc['data'] = {}

    relation = {}
    # set type / subtype
    relation['type'] = 'relation'
    if not relation_subtype == self.RELATION_REGULAR:
      relation['subtype'] = relation_subtype

    # set source
    if source_id and source_type:
      if not source_type in EIQEntity.ENTITY_TYPES:
        raise Exception('Expecting source_type from EIQEntity.ENTITY_TYPES')
      relation['source'] = source_id
      relation['source_type'] = source_type

    # set target
    if target_id and target_type:
      if not target_type in EIQEntity.ENTITY_TYPES:
        raise Exception('Expecting target_type from EIQEntity.ENTITY_TYPES')
      relation['target'] = target_id
      relation['target_type'] = target_type

    self.__doc['data']['data'] = relation

  def set_source(self, source_id, source_type):
    if not self.__is_relation_set:
      raise Exception('You need to set a relation subtype first using set_relation(...)')
    if not source_type in EIQEntity.ENTITY_TYPES:
      raise Exception('Expecting source_type from EIQEntity.ENTITY_TYPES')
    self.__doc['data']['data']['source'] = source_id
    self.__doc['data']['data']['source_type'] = source_type
  
  def set_target(self, target_id, target_type):
    if not self.__is_relation_set:
      raise Exception('You need to set a relation subtype first using set_relation(...)')
    if not target_type in EIQEntity.ENTITY_TYPES:
      raise Exception('Expecting target_type from EIQEntity.ENTITY_TYPES')
    self.__doc['data']['data']['target'] = target_id
    self.__doc['data']['data']['target_type'] = target_type

  def get_as_dict(self):
    return self.__doc

  def get_as_json(self):
    return json.dumps(self.__doc)

def timestamp_to_eiq_utc(timestamp):
  return time.strftime('%Y-%m-%dT%H:%M:%S%z', time.gmtime(int(timestamp)))

if __name__ == '__main__':
  pass
