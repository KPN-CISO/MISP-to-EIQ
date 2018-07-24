#!/usr/bin/env python3

import json, urllib.request, ssl, hashlib
import eiqjson

class EIQApi:
  def __init__(self, host=None, username=None, password=None, source=None, use_ssl=True, insecure=False):
    self.host = host
    self.username = username
    self.password = password
    self.source = source
    self.ssl = use_ssl
    self.insecure = insecure

  def set_host(self, host):
    self.host = host

  def set_credentials(self, username, password):
    self.username = username
    self.password = password

  def set_source(self, source):
    self.source = source


  def is_error(self, msg):
    if 'errors' in msg.keys():
      return True
    return False

  """do_call(endpt, method, headers, data, decode_json)
  performs call to self.host + endpt
  this call automatically assumes Content-Type and Accept headers set to application/json
  all headers passed as argument to this call are added to that (and are able to overwrite them)
  """
  def do_call(self, endpt, method, headers = None, data = None, decode_json = True):
    if not self.host:
      raise Exception('call set_host(host) before making calls')

    # set up HTTP headers
    _headers = {}
    _headers['Content-Type'] = 'application/json'
    _headers['Accept'] = 'application/json'
    if headers:
      for key in headers.keys():
        _headers[key] = headers[key]

    # prepare request
    if data:
      req = urllib.request.Request(url=self.host + endpt, data=data, headers=_headers, method=method)
    else:
      req = urllib.request.Request(url=self.host + endpt, headers=_headers, method=method)

    # make connection
    if self.ssl:
      ssl_ctx = ssl.create_default_context()
      if self.insecure:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
      with urllib.request.urlopen(req, context=ssl_ctx) as f:
        ret = f.read().decode('utf-8')
    else:
      with urllib.request.urlopen(req) as f:
        ret = f.read().decode('utf-8')

    # decode & return
    if decode_json:
      try:
        return json.loads(ret)
      except:
        return None
    return ret

  """ do_auth(username, password)
        calls to /auth endpoint
  
        returns: [dict] {'token': '<token>', 'expires_at': '<timestamp>'}, or None on failed call
  """
  def do_auth(self):
    if not self.username or not self.password:
      raise Exception('call set_credentials before do_auth')
    data = '{"username":"%s","password":"%s"}' % (self.username, self.password)
    data = data.encode()
    ret = self.do_call('/auth', 'POST', data=data)
    if ret and 'token' in ret.keys() and 'expires_at' in ret.keys():
      return ret
    return None

  def get_entity(self, u, t):
    return self.__get_entity(u, t)

  def __get_entity(self, uuid_string, token):
    headers = {}
    headers['User-Agent'] = 'eiqlib/1.0'
    headers['Authorization'] = 'Bearer %s' % (token['token'],)
    headers['Cookie'] = 'platform-api-token=%s' % (token['token'],)
    
    # make call
    try:
      ret = self.do_call('/entities/%s' % (uuid_string,), 'GET', headers=headers)
    except:
      return None
    if ret and not self.is_error(ret):
      return ret
    return None

  def __str2uuid(self, s):
    if isinstance(s, str):
      s = s.encode()
    s = hashlib.md5(s).hexdigest()
    return s[:8] + '-' + s[8:12] + '-' + s[12:16] + '-' + s[16:20] + '-' + s[20:]

  """ __get_latest_version_id(self, update_identifier, token)
        a deterministic way to figure out which random-seeming internal EIQ id
        matches "update_identifier"

        returns: ([str] uuid_prev, [str] uuid_this)
          uuid_prev: uuid of the entity to update (or None if none exist)
          uuid_this: uuid to use for this entity
  """
  def get_latest_version_id(self, u, t):
    return self.__get_latest_version_id(u, t)

  def __get_latest_version_id(self, update_identifier, token):
    update_ctr = 0
    latest_version = None

    if isinstance(update_identifier, str):
      update_identifier = update_identifier.encode()

    uuid_string = self.__str2uuid(update_identifier + b'%d' % (update_ctr,))
    while True:
      ret = self.__get_entity(uuid_string, token)
      if ret:
        latest_version = uuid_string
        update_ctr += 1
        uuid_string = self.__str2uuid(update_identifier + b'%d' % (update_ctr,))
      else:
        return (latest_version, uuid_string)

  def get_entity_tags(self, u, t):
    return self.__get_entity_tags(u, t)

  def __get_entity_tags(self, uuid_string, token):
    entity = self.__get_entity(uuid_string, token)
    taxonomies = []
    if entity and 'data' in entity.keys() and 'meta' in entity['data'].keys() and 'taxonomy' in entity['data']['meta'].keys():
      for taxonomy in entity['data']['meta']['taxonomy']:
        taxonomies.append(taxonomy)
    return taxonomies

  """ create_entity(entity_json)
        calls to /entities/ endpoint
        entity_json: [str] currently formatted request body in EIQ-json for new entity
        returns: [python object] parsed json response from api
  """
  def create_entity(self, entity_json, update_identifier=None, token=None):
    # auth token
    if not token:
      token = self.do_auth()
      if not token:
        raise Exception('create_entity was unable to authenticate')

    if update_identifier:
      prev_id, this_id = self.__get_latest_version_id(update_identifier, token)

      # expensive way to update the id, but it keeps the usage of create_entiy simple
      if isinstance(entity_json, bytes):
        entity_json = entity_json.decode('utf-8')
      if prev_id:
        tags = self.__get_entity_tags(prev_id, token)
      else:
        tags = []
      entity_json = json.loads(entity_json)
      entity_json['data']['id'] = this_id
      entity_json['data']['meta']['taxonomy'] = tags
      entity_type = entity_json['data']['data']['type']
      entity_json = json.dumps(entity_json)
      
      # if there was a previous version, we need to let update_entity handle the entire creation process
      # otherwise, let the rest of create_entity handle the call
      if prev_id:
        return self.update_entity(entity_json, prev_id, entity_type, token=token)

    headers = {}
    headers['Authorization'] = 'Bearer %s' % (token['token'],)
    headers['Cookie'] = 'platform-api-token=%s' % (token['token'],)

    if isinstance(entity_json, str):
      entity_json = entity_json.encode()

    # make call
    ret = self.do_call('/entities/', 'POST', headers=headers, data=entity_json)
    if ret:
      return ret
    else:
      return None

  """ update_entity(updated_entity_json, old_entity_id)
        this method makes 2 calls to the /entities/ endpoint
        1) create a "new" entity with all updated information when compared to the old one
        2) create a "stix_update_of" relation between the updated entity and the superseded entity
      updated_entity_json: [str] EIQ json of the new "updated" entity
      old_entity_id: [str] uuid of the superseded entity
      old_entity_type: [str] type of the old entity
      returns: [python object] error python message or None on failure, create_entity object of the new entity on success
  """
  def update_entity(self, updated_entity_json, old_entity_id, old_entity_type, token=None):
    # auth token
    if not token:
      token = self.do_auth()
      if not token:
        raise Exception('update_entity was unable to authenticate')
    headers = {}
    headers['Authorization'] = 'Bearer %s' % (token['token'],)
    headers['Cookie'] = 'platform-api-token=%s' % (token['token'],)

    # make call to create updated entity
    ret = self.create_entity(updated_entity_json, token=token)
    if not ret:
      return None
    if 'errors' in ret:
      return ret
    entity_ret = ret

    # updated entity created, now make it the successor of the old entity
    if 'data' in ret and 'data' in ret['data'] and 'type' in ret['data']['data'] and 'sources' in ret['data'] and len(ret['data']['sources']) > 0:
      source_id = ret['data']['id']
      source_type = ret['data']['data']['type']
      meta_source = ret['data']['sources'][-1]['source_id']
    else:
      return None

    update = eiqjson.EIQRelation()
    update.set_relation(update.RELATION_STIX_UPDATE)
    update.set_source(source_id, source_type)
    update.set_target(old_entity_id, old_entity_type)
    update.set_ingest_source(meta_source)
    ret = self.create_entity(update.get_as_json(), token=token)
    if not ret:
        return None
    if 'errors' in ret:
        return ret
    # on success, return the original create_entity result
    return entity_ret

if __name__ == '__main__':
  pass

