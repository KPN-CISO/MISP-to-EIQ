#!/usr/bin/env python3

import json, time, uuid, sys

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
  ENTITY_TTP = 'ttp'

  ENTITY_TYPES = [
    ENTITY_INDICATOR,
    ENTITY_SIGHTING,
    ENTITY_REPORT,
    ENTITY_TTP
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
  OBSERVABLE_PORT = 'port'
  OBSERVABLE_URI = 'uri'
  OBSERVABLE_DOMAIN = 'domain'
  OBSERVABLE_EMAIL = 'email'

  OBSERVABLE_ORGANIZATION = 'organization'
  OBSERVABLE_MD5 = 'hash-md5'
  OBSERVABLE_SHA1 = 'hash-sha1'
  OBSERVABLE_SHA256 = 'hash-sha256'
  OBSERVABLE_SHA512 = 'hash-sha512'
  OBSERVABLE_FILE = 'file'
  OBSERVABLE_DOMAIN = 'domain'
  OBSERVABLE_EMAIL = 'email'
  OBSERVABLE_EMAIL_SUBJECT = 'email-subject'
  OBSERVABLE_MUTEX = 'mutex'
  OBSERVABLE_TELEPHONE = 'telephone'
  OBSERVABLE_NATIONALITY = 'nationality'
  OBSERVABLE_PERSON = 'person'
  OBSERVABLE_SNORT = 'snort'
  OBSERVABLE_WINREGISTRY = 'winregistry'
  OBSERVABLE_YARA = 'yara'

  OBSERVABLE_TYPES = [
    OBSERVABLE_IPV4,
    OBSERVABLE_URI,
    OBSERVABLE_DOMAIN,
    OBSERVABLE_EMAIL,
    OBSERVABLE_ORGANIZATION
  ]

  OBSERVABLE_LINK_OBSERVED = 'observed'
  OBSERVABLE_LINK_TEST_MECHANISM = 'test-mechanism'
  OBSERVABLE_LINK_SIGHTED = 'sighted'

  OBSERVABLE_LINK_TYPES = [
    OBSERVABLE_LINK_OBSERVED,
    OBSERVABLE_LINK_TEST_MECHANISM,
    OBSERVABLE_LINK_SIGHTED
  ]

  INDICATOR_MALICIOUS_EMAIL = 'Malicious E-mail'
  INDICATOR_IP_WATCHLIST = 'IP Watchlist'
  INDICATOR_FILE_HASH_WATCHLIST = 'File Hash Watchlist'
  INDICATOR_DOMAIN_WATCHLIST = 'Domain Watchlist'
  INDICATOR_URL_WATCHLIST = 'URL Watchlist'
  INDICATOR_MALWARE_ARTIFACTS = 'Malware Artifacts'
  INDICATOR_C2 = 'C2'
  INDICATOR_ANONYMIZATION = 'Anonymization'
  INDICATOR_EXFILTRATION = 'Exfiltration'
  INDICATOR_HOST_CHARACTERISTICS = 'Host Characteristics'
  INDICATOR_COMPROMISED_PKI_CERTIFICATE = 'Compromised PKI Certificate'
  INDICATOR_LOGIN_NAME = 'Login Name'
  INDICATOR_IMEI_WATCHLIST = 'IMEI Watchlist'
  INDICATOR_IMSI_WATCHLIST = 'IMSI Watchlist'
  INDICATOR_TYPES = [
    INDICATOR_MALICIOUS_EMAIL,
    INDICATOR_IP_WATCHLIST,
    INDICATOR_FILE_HASH_WATCHLIST,
    INDICATOR_DOMAIN_WATCHLIST,
    INDICATOR_URL_WATCHLIST,
    INDICATOR_MALWARE_ARTIFACTS,
    INDICATOR_C2,
    INDICATOR_ANONYMIZATION,
    INDICATOR_EXFILTRATION,
    INDICATOR_HOST_CHARACTERISTICS,
    INDICATOR_COMPROMISED_PKI_CERTIFICATE,
    INDICATOR_LOGIN_NAME,
    INDICATOR_IMEI_WATCHLIST,
    INDICATOR_IMSI_WATCHLIST
  ]

  TTP_ADVANTAGE = 'Advantage'
  TTP_ADVANTAGE_ECONOMIC = 'Advantage - Economic'
  TTP_ADVANTAGE_MILITARY = 'Advantage - Military'
  TTP_ADVANTAGE_POLITICAL = 'Advantage - Political'
  TTP_THEFT = 'Theft'
  TTP_THEFT_INTELLECTUAL_PROPERTY = 'Theft - Intellectual Property'
  TTP_THEFT_CREDENTIAL_THEFT = 'Theft - Credential Theft'
  TTP_THEFT_IDENTITY_THEFT = 'Theft - Identity Theft'
  TTP_THEFT_THEFT_OF_PROPRIETARY_INFORMATION = 'Theft - Theft of Proprietary Information'
  TTP_ACCOUNT_TAKEOVER = 'Account Takeover'
  TTP_BRAND_DAMAGE = 'Brand Damage'
  TTP_COMPETITIVE_ADVANTAGE = 'Competitve Advantage'
  TTP_DEGRADATION_OF_SERVICE = 'Degradation of Service'
  TTP_DENIAL_AND_DECEPTION = 'Denial and Deception'
  TTP_DESTRUCTION = 'Destruction'
  TTP_DISRUPTION = 'Disruption'
  TTP_EMBARRASSMENT = 'Embarrassment'
  TTP_EXPOSURE = 'Exposure'
  TTP_EXTORTION = 'Extortion'
  TTP_FRAUD = 'Fraud'
  TTP_HARASSMENT = 'Harassment'
  TTP_ICS_CONTROL = 'ICS Control'
  TTP_TRAFFIC_DIVERSION = 'Traffic Diversion'
  TTP_UNAUTHORIZED_ACCESS = 'Unauthorized Access'

  TTP_TYPES = [
    TTP_ADVANTAGE,
    TTP_ADVANTAGE_ECONOMIC,
    TTP_ADVANTAGE_MILITARY,
    TTP_ADVANTAGE_POLITICAL,
    TTP_THEFT,
    TTP_THEFT_INTELLECTUAL_PROPERTY,
    TTP_THEFT_CREDENTIAL_THEFT,
    TTP_THEFT_IDENTITY_THEFT,
    TTP_THEFT_THEFT_OF_PROPRIETARY_INFORMATION,
    TTP_ACCOUNT_TAKEOVER,
    TTP_BRAND_DAMAGE,
    TTP_COMPETITIVE_ADVANTAGE,
    TTP_DEGRADATION_OF_SERVICE,
    TTP_DENIAL_AND_DECEPTION,
    TTP_DESTRUCTION,
    TTP_DISRUPTION,
    TTP_EMBARRASSMENT,
    TTP_EXPOSURE,
    TTP_EXTORTION,
    TTP_FRAUD,
    TTP_HARASSMENT,
    TTP_ICS_CONTROL,
    TTP_TRAFFIC_DIVERSION,
    TTP_UNAUTHORIZED_ACCESS
  ]

  CLASSIFICATION_BAD = 'bad'
  CLASSIFICATION_GOOD = 'good'
  CLASSIFICATION_UNKNOWN = 'unknown'

  CLASSIFICATION_TYPES = [
    CLASSIFICATION_BAD,
    CLASSIFICATION_GOOD,
    CLASSIFICATION_UNKNOWN
  ]

  CONFIDENCE_LOW = 'low'
  CONFIDENCE_MEDIUM = 'medium'
  CONFIDENCE_HIGH = 'high'

  CONFIDENCE_TYPES = [
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH
  ]

  def __init__(self):
    self.__is_entity_set = False
    self.__doc = {}

  def set_entity(self, entity_type, entity_title = '', entity_description = '', observed_time = '', source = '', source_reliability = 'A', tlp = 'RED', confidence = 'Unknown', impact = 'Unknown'):
    if not entity_type in self.ENTITY_TYPES:
      raise Exception('Expecting entity_type from ENTITY_TYPES')

    self.__is_entity_set  = True

    entity = {}
    
    # data structure: this entity
    # contains: type, confidence, likely_impact, types, title, description, description_structuring_format & handling
    entity['data'] = {}
    entity['data']['type'] = entity_type
    entity['data']['title'] = entity_title
    entity['data']['description'] = entity_description
    entity['data']['description_structuring_format'] = 'html'
    entity['data']['types'] = []
    # has to set: types, confidence, impact, tlp

    # meta structure: what is around this entity
    # source, source_reliability, estimated_observed_time, tags, taxonomy, manual_extracts, tlp_color, made_with_builder
    entity['meta'] = {}
    entity['meta']['source'] = source
    entity['meta']['source_reliability'] = source_reliability
    entity['meta']['estimated_observed_time'] = observed_time
    entity['meta']['tags'] = []
    entity['meta']['taxonomy'] = []
    entity['meta']['manual_extracts'] = []
    entity['meta']['made_with_builder'] = '1.10_1' # ugly hack, perhaps necessary, perhaps not
    entity['meta']['half_life'] = 182 # EIQ default of half a year

    # intel_sets: unknown, empty list
    entity['intel_sets'] = []

    self.__doc['data'] = entity

    self.set_entity_confidence(confidence)
    
    if entity_type == self.ENTITY_INDICATOR or entity_type == self.ENTITY_SIGHTING:
      self.set_entity_impact(impact)
    
    self.set_entity_tlp(tlp)

  def set_id(self, id_string):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['id'] = id_string

  def set_entity_source(self, source, source_reliability = 'A'):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['meta']['source'] = source
    self.__doc['data']['meta']['source_reliability'] = source_reliability

  def set_entity_title(self, title):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['data']['title'] = title

  def set_entity_description(self, description, description_format='html'):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['data']['description'] = description
    self.__doc['data']['data']['description_structuring_format'] = description_format

  def get_entity_description(self):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    return self.__doc['data']['data']['description']

  def set_entity_observed_time(self, observed_time):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['meta']['estimated_observed_time'] = observed_time

  def set_entity_reliability(self, reliability):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['meta']['source_reliability'] = reliability

  def set_entity_confidence(self, confidence = 'Unknown'):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['data']['confidence'] = {}
    self.__doc['data']['data']['confidence']['type'] = 'confidence'
    self.__doc['data']['data']['confidence']['value'] = confidence

  def set_entity_impact(self, impact = 'Unknown'):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    # at least sightings and incidators both have an impact setting, but both address it by a different name (but with an identical structure)
    if self.__doc['data']['data']['type'] == self.ENTITY_SIGHTING:
      impact_key = 'impact'
    elif self.__doc['data']['data']['type'] == self.ENTITY_INDICATOR:
      impact_key = 'likely_impact'
    else:
      raise Exception('impact is not defined for this entity type')
    self.__doc['data']['data'][impact_key] = {}
    self.__doc['data']['data'][impact_key]['type'] = 'statement'
    self.__doc['data']['data'][impact_key]['value_vocab'] = '{http://stix.mitre.org/default_vocabularies-1}HighMediumLowVocab-1.0'
    self.__doc['data']['data'][impact_key]['value'] = impact

  def set_entity_tlp(self, tlp):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    self.__doc['data']['meta']['tlp_color'] = tlp.upper()
    self.__doc['data']['data']['handling'] = [{}]
    self.__doc['data']['data']['handling'][0]['type'] = 'marking-specification'
    self.__doc['data']['data']['handling'][0]['marking_structures'] = [{}]
    self.__doc['data']['data']['handling'][0]['marking_structures'][0]['marking_structure_type'] = 'tlp'
    self.__doc['data']['data']['handling'][0]['marking_structures'][0]['color'] = tlp.upper()
    self.__doc['data']['data']['handling'][0]['marking_structures'][0]['type'] = 'marking-structure'

  def add_indicator_type(self, indicator_type):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    if not indicator_type in self.INDICATOR_TYPES:
      raise Exception('%s is not a member of INDICATOR_TYPES' % (indicator_type,))
    if not 'types' in self.__doc['data']['data'].keys():
      self.__doc['data']['data']['types'] = []

    # only add unique values
    indicator_type_object = { 'value': indicator_type }
    if not indicator_type_object in self.__doc['data']['data']['types']:
      self.__doc['data']['data']['types'].append({'value': indicator_type})

  def add_ttp_type(self, ttp_type):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    if not ttp_type in self.TTP_TYPES:
      raise Exception('%s is not a member of TTP_TYPES' % (ttp_type,))
    if not 'intended_effects' in self.__doc['data']['data'].keys():
      self.__doc['data']['data']['intended_effects'] = []

    # only add unique values
    ttp_type_object = { 'type': 'statement', 'value': ttp_type }
    if not ttp_type_object in self.__doc['data']['data']['intended_effects']:
      self.__doc['data']['data']['intended_effects'].append(ttp_type_object)

  def add_observable(self, extract_type, value, classification = '', confidence = '', link_type = OBSERVABLE_LINK_OBSERVED):
#    if not observable_type in self.OBSERVABLE_TYPES:
#      raise Exception('Expecting observable_type from OBSERVABLE_TYPES')
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    if not 'manual_extracts' in self.__doc['data']['meta'].keys():
      self.__doc['data']['meta']['manual_extracts'] = []
    if not link_type in self.OBSERVABLE_LINK_TYPES:
      raise Exception('Observable link type %s is not a valid link type' % (link_type,))

    extract = {}

    extract['value'] = value
    extract['kind'] = extract_type
    extract['link_type'] = link_type

    if not classification in self.CLASSIFICATION_TYPES:
      extract['classification'] = self.CLASSIFICATION_UNKNOWN
    else:
      if classification == self.CLASSIFICATION_BAD:
        if not confidence in self.CONFIDENCE_TYPES:
          extract['confidence'] = self.CONFIDENCE_LOW
        else:
          extract['confidence'] = confidence
      extract['classification'] = classification

    self.__doc['data']['meta']['manual_extracts'].append(extract)

  def add_sighting(self, extract_type, value, classification = '', confidence = ''):
#    if not extract_type in self.OBSERVABLE_TYPES:
#      raise Exception('Expecting observable_type from OBSERVABLE_TYPES')
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    if not 'manual_extracts' in self.__doc['data']['meta'].keys():
      self.__doc['data']['meta']['manual_extracts'] = []

    extract = {}

    extract['value'] = value
    extract['kind'] = extract_type
    extract['link_type'] = 'sighted'

    if not classification in self.CLASSIFICATION_TYPES:
      extract['classification'] = self.CLASSIFICATION_UNKNOWN
    else:
      if classification == self.CLASSIFICATION_BAD:
        if not confidence in self.CONFIDENCE_TYPES:
          extract['confidence'] = self.CONFIDENCE_LOW
        else:
          extract['confidence'] = confidence
      extract['classification'] = classification

    self.__doc['data']['meta']['manual_extracts'].append(extract)

  def add_test_mechanism(self, extract_type, value, classification = '', confidence = ''):
#    if not observable_type in self.OBSERVABLE_TYPES:
#      raise Exception('Expecting observable_type from OBSERVABLE_TYPES')
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    if not 'manual_extracts' in self.__doc['data']['meta'].keys():
      self.__doc['data']['meta']['manual_extracts'] = []

    extract = {}

    extract['value'] = value
    extract['kind'] = extract_type
    extract['link_type'] = 'test-mechanism'

    if not classification in self.CLASSIFICATION_TYPES:
      extract['classification'] = self.CLASSIFICATION_UNKNOWN
    else:
      if classification == self.CLASSIFICATION_BAD:
        if not confidence in self.CONFIDENCE_TYPES:
          extract['confidence'] = self.CONFIDENCE_LOW
        else:
          extract['confidence'] = confidence
      extract['classification'] = classification

    self.__doc['data']['meta']['manual_extracts'].append(extract)

  def get_as_dict(self):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    if self.__doc['data']['data']['type'] == self.ENTITY_INDICATOR and not 'types' in self.__doc['data']['data'].keys():
      sys.stderr.write('[!] no indicator type was set using add_indicator_type(indicator_type)\n')
    return self.__doc

  def get_as_json(self):
    if not self.__is_entity_set:
      raise Exception('You need to set an entity first using set_entity(...)')
    if self.__doc['data']['data']['type'] == self.ENTITY_INDICATOR and not 'types' in self.__doc['data']['data'].keys():
      sys.stderr.write('[!] no indicator type was set using add_indicator_type(indicator_type)\n')
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

  def set_relation(self, relation_subtype, source_id = None, source_type = None, target_id = None, target_type = None, ingest_source = None):
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

    self.__doc['data']['meta'] = {}
    if ingest_source:
      self.__doc['data']['meta']['source'] = ingest_source
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

  def set_ingest_source(self, source):
    if not self.__is_relation_set:
      raise Exception('You need to set a relation subtype first using set_relation(...)')
    self.__doc['data']['meta']['source'] = source

  def get_as_dict(self):
    return self.__doc

  def get_as_json(self):
    return json.dumps(self.__doc)

def timestamp_to_eiq_utc(timestamp):
  return time.strftime('%Y-%m-%dT%H:%M:%S%z', time.gmtime(int(timestamp)))

if __name__ == '__main__':
  pass
