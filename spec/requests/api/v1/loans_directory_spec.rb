# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'Diretório interno de Empréstimos', type: :request do
  let(:directory_key) { 'synthetic-directory-key-32-characters-long' }
  let(:operator) do
    User.create!(name: 'Synthetic Operator', email: 'operator-loans@example.invalid',
                 password: 'Test123!@', password_confirmation: 'Test123!@', confirmed_at: Time.current)
  end
  let(:target) do
    User.create!(name: 'Synthetic Target', email: 'target-loans@example.invalid',
                 password: 'Test123!@', password_confirmation: 'Test123!@', confirmed_at: Time.current)
  end
  let(:oauth_app) { OauthApplication.create!(name: 'synthetic-loans-test', redirect_uri: 'https://localhost/callback', scopes: 'read write') }
  let(:token) { Doorkeeper::AccessToken.create!(application: oauth_app, resource_owner_id: operator.id, expires_in: 3600) }
  let(:headers) { { 'Authorization' => "Bearer #{token.token}", 'X-Loans-Directory-Key' => directory_key, 'Host' => 'localhost' } }

  before do
    @previous_key = ENV['LOANS_DIRECTORY_KEY']
    ENV['LOANS_DIRECTORY_KEY'] = directory_key
    Rails.cache.clear
  end

  after do
    ENV['LOANS_DIRECTORY_KEY'] = @previous_key
    Rails.cache.clear
  end

  it 'pesquisa e resolve com chave dedicada e bearer, sem users.read nem dados extras' do
    target
    post '/api/v1/internal/loans-directory/search', params: { loans_directory_query: 'Synthetic Target' }, headers: headers, as: :json
    expect(response).to have_http_status(:ok)
    row = response.parsed_body.fetch('data').find { |entry| entry['id'] == target.id.to_s }
    expect(row).to include('name' => 'Synthetic Target', 'confirmed' => true)
    expect(row.keys).to contain_exactly('id', 'name', 'confirmed')

    post '/api/v1/internal/loans-directory/resolve', params: { loans_directory_user_id: target.id }, headers: headers, as: :json
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch('data').fetch('id')).to eq(target.id.to_s)
  end

  it 'exige chave dedicada e bearer, sem aceitar credenciais genéricas ou ausentes' do
    post '/api/v1/internal/loans-directory/search', params: {}, headers: headers.except('X-Loans-Directory-Key'), as: :json
    expect(response).to have_http_status(:unauthorized)
    post '/api/v1/internal/loans-directory/search', params: {}, headers: headers.merge('X-Loans-Directory-Key' => 'wrong'), as: :json
    expect(response).to have_http_status(:unauthorized)
    post '/api/v1/internal/loans-directory/search', params: {}, headers: headers.except('Authorization'), as: :json
    expect(response).to have_http_status(:unauthorized)
  end

  it 'nega token revogado mesmo quando o cache está vazio' do
    token.revoke
    Rails.cache.clear
    post '/api/v1/internal/loans-directory/search', params: {}, headers: headers, as: :json
    expect(response).to have_http_status(:unauthorized)
    post '/api/v1/internal/loans-directory/verify', params: {}, headers: headers, as: :json
    expect(response).to have_http_status(:unauthorized)
  end

  it 'confirma apenas a identidade autenticada para a validação do módulo' do
    post '/api/v1/internal/loans-directory/verify', params: {}, headers: headers, as: :json
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch('data')).to eq('id' => operator.id.to_s)
  end

  it 'recusa identificadores inválidos e não inventa usuários' do
    post '/api/v1/internal/loans-directory/resolve', params: { loans_directory_user_id: 'not-a-uuid' }, headers: headers, as: :json
    expect(response).to have_http_status(:unprocessable_entity)
    post '/api/v1/internal/loans-directory/resolve', params: { loans_directory_user_id: SecureRandom.uuid }, headers: headers, as: :json
    expect(response).to have_http_status(:not_found)
  end

  it 'limita páginas e não apresenta parâmetros sensíveis em texto' do
    post '/api/v1/internal/loans-directory/search', params: { loans_directory_query: 'x' * 101 }, headers: headers, as: :json
    expect(response).to have_http_status(:unprocessable_entity)
    post '/api/v1/internal/loans-directory/search', params: { page_size: 21 }, headers: headers, as: :json
    expect(response).to have_http_status(:unprocessable_entity)
    filter = ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters)
    expect(filter.filter('loans_directory_query' => 'private').fetch('loans_directory_query')).to eq('[FILTERED]')
  end

  it 'mantém o diretório geral protegido para operador sem users.read' do
    get '/api/v1/users', headers: headers, as: :json
    expect(response).to have_http_status(:forbidden)
  end

  it 'limita requisições e falha fechada se o contador estiver indisponível' do
    allow(Rails.cache).to receive(:increment).and_return(61)
    post '/api/v1/internal/loans-directory/search', params: {}, headers: headers, as: :json
    expect(response).to have_http_status(:too_many_requests)
    allow(Rails.cache).to receive(:increment).and_return(nil)
    post '/api/v1/internal/loans-directory/search', params: {}, headers: headers, as: :json
    expect(response).to have_http_status(:service_unavailable)
  end
end
