# frozen_string_literal: true

# A autorização de carteira é verificada pelo serviço de Empréstimos antes
# desta chamada; esta rota aceita somente sua chave própria e o token real.
class Api::V1::LoansDirectoryController < Api::BaseController
  prepend_before_action :require_bearer!
  prepend_before_action :require_directory_key!
  before_action :require_active_bearer!
  before_action :limit_requests!

  MAX_PAGE_SIZE = 20
  MAX_PAGE = 200
  MAX_REQUEST_BYTES = 4096

  def verify
    render json: { data: { id: current_user.id.to_s } }
  end

  def search
    return head :payload_too_large if request.content_length.to_i > MAX_REQUEST_BYTES
    query = params[:loans_directory_query]
    return head :unprocessable_entity unless query.nil? || (query.is_a?(String) && query.length <= 100)

    page = parse_positive(params[:page], 1, MAX_PAGE)
    size = parse_positive(params[:page_size], MAX_PAGE_SIZE, MAX_PAGE_SIZE)
    return head :unprocessable_entity unless page && size

    # O driver parametrizado evita interpolação SQL e não envia os termos ao log
    # de binds do ActiveRecord. O filtro Rails também mascara parâmetros no log HTTP.
    term = "%#{ActiveRecord::Base.sanitize_sql_like(query.to_s.strip)}%"
    rows = raw_rows(<<~SQL, [term, size + 1, (page - 1) * size])
      SELECT id::text, COALESCE(NULLIF(display_name, ''), name) AS name,
             (confirmed_at IS NOT NULL) AS confirmed
      FROM users WHERE name ILIKE $1 OR email ILIKE $1
      ORDER BY name ASC, id ASC LIMIT $2 OFFSET $3
    SQL
    render json: { data: rows.first(size), page: page, has_more: rows.length > size }
  end

  def resolve
    return head :payload_too_large if request.content_length.to_i > MAX_REQUEST_BYTES
    id = params[:loans_directory_user_id]
    return head :unprocessable_entity unless id.is_a?(String) && id.match?(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i)

    rows = raw_rows(<<~SQL, [id])
      SELECT id::text, COALESCE(NULLIF(display_name, ''), name) AS name,
             (confirmed_at IS NOT NULL) AS confirmed FROM users WHERE id = $1::uuid LIMIT 1
    SQL
    return head :not_found if rows.empty?

    render json: { data: rows.first }
  end

  private

  def require_directory_key!
    expected = ENV['LOANS_DIRECTORY_KEY'].to_s
    supplied = request.headers['X-Loans-Directory-Key'].to_s
    return if expected.bytesize >= 32 && supplied.bytesize == expected.bytesize &&
              ActiveSupport::SecurityUtils.secure_compare(expected, supplied)

    head :unauthorized
  end

  def require_bearer!
    return if request.headers['Authorization'].to_s.match?(/\ABearer\s+\S+\z/)

    head :unauthorized
  end

  def require_active_bearer!
    return if @doorkeeper_token && !@doorkeeper_token.revoked? && !@doorkeeper_token.expired?

    head :unauthorized
  end

  def limit_requests!
    return head :unauthorized unless current_user

    category = action_name == 'verify' ? 'verify' : 'directory'
    max = category == 'verify' ? 600 : 60
    key = "loans-directory:#{category}:#{Digest::SHA256.hexdigest(current_user.id.to_s)}:#{Time.now.to_i / 60}"
    Rails.cache.write(key, 0, unless_exist: true, expires_in: 70.seconds)
    count = Rails.cache.increment(key, 1, expires_in: 70.seconds)
    return head :service_unavailable unless count
    return head :too_many_requests if count > max
  end

  def parse_positive(value, default, maximum)
    return default if value.nil?
    return nil unless value.to_s.match?(/\A[0-9]+\z/)

    number = value.to_i
    number.between?(1, maximum) ? number : nil
  end

  def raw_rows(sql, binds)
    ActiveRecord::Base.connection_pool.with_connection do |connection|
      connection.raw_connection.exec_params(sql, binds).map do |row|
        confirmed = row.fetch('confirmed')
        { id: row.fetch('id'), name: row.fetch('name'), confirmed: confirmed == true || confirmed == 't' }
      end
    end
  end
end
