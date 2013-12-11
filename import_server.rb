require 'bundler'
Bundler.require
require 'sinatra'
require 'openssl'
require 'base64'
require 'json'
require 'pp'

AWS.config(
  :access_key_id => ENV['AWS_SECRET_KEY_ID'],
  :secret_access_key => ENV['AWS_SECRET_KEY'])

post "/import" do
  events = JSON.parse params['mandrill_events']
  halt 401, 'Invalid Signature' and return unless ENV['WEBHOOK_KEY'].split(";").detect{|key| webhook_valid?(key, request.url, params, request.env['HTTP_X_MANDRILL_SIGNATURE'])}

  events.each do |evt|
    raise "Unknown event type '#{evt['event']}'" unless evt['event'] == 'inbound'

    message = evt['msg']
    process_inbound message
  end

  status 200
end

head "/import" do
  status 200
end

def process_inbound(message)
  endpoint = message['email'].split('@').first

  attachments = message.delete 'attachments'
  message.delete 'raw_msg'

  Hash(attachments).each do |name, attach|
    content = attach['content']
    type = attach['type']
    if attach['base64']
      content = Base64.decode64(content)
    end

    object_name = "#{Date.today.to_s}_#{endpoint}_#{SecureRandom.uuid}_#{name}"
    url = upload_file(object_name, content, type)
    queue_import(url, endpoint, provider: 'mandrill', message: message)
  end
end

def upload_file(object_name, data, content_type)
  s3 = AWS::S3.new
  bucket = s3.buckets[ENV['IMPORT_BUCKET_NAME']]
  obj = bucket.objects.create object_name, data, content_type: content_type
  pp obj
  {bucket: bucket.name, key: obj.key}
end

def queue_import(object_url, endpoint, **data)
  body = {action: 'import', endpoint: endpoint, object: object_url}.merge(data)

  sqs = AWS::SQS.new
  queue = sqs.queues.named(ENV['IMPORT_QUEUE_NAME'])
  sent = queue.send_message JSON.generate(body)
  pp sent
end

def webhook_valid? key, url, params, signature
  data = url
  params.sort.each {|k,v| data = url + k + v}
  digest = OpenSSL::Digest::Digest.new('sha1')
  expected = Base64.encode64(OpenSSL::HMAC.digest(digest, key, data)).strip
  expected == signature
end
