require 'json'
require 'sinatra/base'
require 'erubi'
require 'mysql2'
require 'mysql2-cs-bind'
require 'openssl'

module Torb
  class Web < Sinatra::Base
    configure :development do
      require 'sinatra/reloader'
      register Sinatra::Reloader
      require 'pry'
    end

    set :root, File.expand_path('../..', __dir__)
    set :sessions, key: 'torb_session', expire_after: 3600
    set :session_secret, 'tagomoris'
    set :protection, frame_options: :deny

    set :erb, escape_html: true

    set :login_required, ->(value) do
      condition do
        if value && !get_login_user
          halt_with_error 401, 'login_required'
        end
      end
    end

    set :admin_login_required, ->(value) do
      condition do
        if value && !get_login_administrator
          halt_with_error 401, 'admin_login_required'
        end
      end
    end

    before '/api/*|/admin/api/*' do
      content_type :json
    end

    helpers do
      def db
        Thread.current[:db] ||= Mysql2::Client.new(
          host: ENV['DB_HOST'],
          port: ENV['DB_PORT'],
          username: ENV['DB_USER'],
          password: ENV['DB_PASS'],
          database: ENV['DB_DATABASE'],
          database_timezone: :utc,
          cast_booleans: true,
          reconnect: true,
          init_command: 'SET SESSION sql_mode="STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"',
        )
      end

      def get_events(only_public: true, need_reservasion: true)
        where = only_public ? 'WHERE public_fg = 1' : ''

        @cached_event_records = db.query("SELECT * FROM events #{where} ORDER BY id ASC").each_with_object({}) do |event, hash|
          hash[event['id']] = event
        end

        event_ids = @cached_event_records.keys
        # sheets はマスタっぽくて使い回せそうなので、そうして見ます
        sheets = db.query('SELECT * FROM sheets ORDER BY `rank`, num')

        events = event_ids.map do |event_id|
          event = get_event(event_id, nil, sheets: sheets, need_reservasion: need_reservasion)
          event['sheets'].each { |sheet| sheet.delete('detail') }
          event
        end

        events
      end

      def fetch_event_record(event_id)
        @cached_event_records ||= {}

        @cached_event_records[event_id] ||= db.xquery('SELECT * FROM events WHERE id = ? LIMIT 1', event_id).first
      end

      def fetch_reservations(event_id)
        @reservations ||= {}

        @reservations[event_id] ||= db.xquery('SELECT sheet_id, reserved_at, user_id FROM reservations WHERE event_id = ? AND canceled_at IS NULL', event_id)
      end

      def get_event(event_id, login_user_id = nil, sheets: nil, need_reservasion: true)
        event = fetch_event_record(event_id)
        return unless event

        # zero fill
        event['total']   = 0
        event['remains'] = need_reservasion ? 0 : 1000 - db.xquery('SELECT count(*) AS cnt FROM reservations WHERE event_id = ? AND canceled_at IS NULL', event_id).first['cnt']
        event['sheets'] = {}
        %w[S A B C].each do |rank|
          event['sheets'][rank] = { 'total' => 0, 'remains' => 0, 'detail' => [] }
        end

        master_reservations = fetch_reservations(event_id).to_a if need_reservasion

        sheets ||= db.query('SELECT * FROM sheets ORDER BY `rank`, num')
        sheets.each do |master_sheet|
          sheet = master_sheet.dup

          event['sheets'][sheet['rank']]['price'] ||= event['price'] + sheet['price']
          # TODO: これ sheets の count と同じっぽい
          event['total'] += 1
          # TODO: これも sheets where rank = X の count と同じっぽい
          event['sheets'][sheet['rank']]['total'] += 1

          if need_reservasion
            reservation = master_reservations.select { |r| r['sheet_id'] == sheet['id'] }.sort { |a, b| b['reserved_at'].to_i <=> a['reserved_at'].to_i }.first
            if reservation
              sheet['mine']        = true if login_user_id && reservation['user_id'] == login_user_id
              sheet['reserved']    = true
              sheet['reserved_at'] = reservation['reserved_at'].to_i
            end
          end

          event['sheets'][sheet['rank']]['detail'].push(sheet)

          sheet.delete('id')
          sheet.delete('price')
          sheet.delete('rank')
        end

        reserves = reserved_sheets_by_event_id[event['id']]
        event['remains'] = reserves.nil? ? 1000 : 1000 - reserves.values.inject(&:+)
        %w(S A B C).each do |rank|
          if reserves.nil?
            event['sheets'][rank]['remains'] = sheets_by_rank[rank]
          else
            event['sheets'][rank]['remains'] = sheets_by_rank[rank] - (reserves[rank] || 0)
          end
        end

        # TODO: あんま効果なさそうだけど SQL で AS 指定すれば良さそう
        event['public'] = event.delete('public_fg')
        event['closed'] = event.delete('closed_fg')

        event
      end

      def reserved_sheets_by_event_id
        @reserved_sheets_by_event_id ||= begin
          rows = db.query('select event_id, sheet_rank, count(sheet_rank) as cnt from reservations where canceled_at IS NULL group by event_id, sheet_rank order by event_id')
          reserves_by_event = {}
          rows.group_by { |row| row['event_id'] }.each do |event_id, records|
            reserves_by_event[event_id] = {}
            records.each { |record| reserves_by_event[event_id][record['sheet_rank']] = record['cnt'] }
          end
          reserves_by_event
        end
      end

      def sheets_by_rank
        @sheets_by_rank ||= begin
          sheets_by_rank = {}
          rows = db.query('SELECT `rank`, count(`rank`) AS cnt FROM sheets GROUP BY `rank`')
          rows.each { |row| sheets_by_rank[row['rank']] = row['cnt'] }
          sheets_by_rank
        end
      end

      def sanitize_event(event)
        sanitized = event.dup  # shallow clone
        sanitized.delete('price')
        sanitized.delete('public')
        sanitized.delete('closed')
        sanitized
      end

      # # リクエスト内でキャッシュ
      # def fetch_event(event_id)
      #   @cached_events ||= {}
      #   return @cached_events[event_id] if @cached_events.key?(event_id)

      #   get_event(event_id).tap do |x|
      #     @cached_events[event_id] = x
      #   end
      # end
      alias fetch_event get_event

      def get_login_user
        user_id = session[:user_id]
        return unless user_id
        db.xquery('SELECT id, nickname FROM users WHERE id = ?', user_id).first
      end

      def get_login_administrator
        administrator_id = session['administrator_id']
        return unless administrator_id
        db.xquery('SELECT id, nickname FROM administrators WHERE id = ?', administrator_id).first
      end

      def validate_rank(rank)
        ranks = %w[S A B C]
        return true if ranks.include?(rank)
        false
        # db.xquery('SELECT COUNT(*) AS total_sheets FROM sheets WHERE `rank` = ?', rank).first['total_sheets'] > 0
      end

      def body_params
        @body_params ||= JSON.parse(request.body.tap(&:rewind).read)
      end

      def halt_with_error(status = 500, error = 'unknown')
        halt status, { error: error }.to_json
      end

      def render_report_csv(reports)
        reports = reports.sort_by { |report| report[:sold_at] }

        keys = %i[reservation_id event_id rank num price user_id sold_at canceled_at]
        body = keys.join(',')
        body << "\n"
        reports.each do |report|
          body << report.values_at(*keys).join(',')
          body << "\n"
        end

        headers({
          'Content-Type'        => 'text/csv; charset=UTF-8',
          'Content-Disposition' => 'attachment; filename="report.csv"',
        })
        body
      end
    end

    get '/' do
      @user   = get_login_user
      @events = get_events(need_reservasion: false).map(&method(:sanitize_event))
      erb :index
    end

    get '/initialize' do
      system "../../db/init.sh"

      status 204
    end

    post '/api/users' do
      nickname   = body_params['nickname']
      login_name = body_params['login_name']
      password   = body_params['password']

      db.query('BEGIN')
      begin
        duplicated = db.xquery('SELECT * FROM users WHERE login_name = ?', login_name).first
        if duplicated
          db.query('ROLLBACK')
          halt_with_error 409, 'duplicated'
        end

        db.xquery('INSERT INTO users (login_name, pass_hash, nickname) VALUES (?, SHA2(?, 256), ?)', login_name, password, nickname)
        user_id = db.last_id
        db.query('COMMIT')
      rescue => e
        warn "rollback by: #{e}"
        db.query('ROLLBACK')
        halt_with_error
      end

      status 201
      { id: user_id, nickname: nickname }.to_json
    end

    # マイページ
    get '/api/users/:id', login_required: true do |user_id|
      if user_id != session[:user_id].to_s
        halt_with_error 403, 'forbidden'
      end
      user = db.xquery('SELECT id, nickname FROM users WHERE id = ?', user_id).first

      master_query = <<~SQL
      SELECT
          r.*,
          s.rank AS sheet_rank,
          s.num AS sheet_num,
          s.price AS sheet_price,
          e.price AS event_price
      FROM
          reservations r
          INNER JOIN
              sheets s
          ON  s.id = r.sheet_id
          INNER JOIN
              events e
          ON  e.id = r.event_id
      WHERE
          r.user_id = ?
      SQL
      reservation_master = db.xquery(master_query, user['id'])

      rows = reservation_master.sort_by { |res| res['canceled_at'] || res['reserved_at'] }.reverse.slice(0..4)

      event_cache = {}

      recent_reservations = rows.map do |row|
        event = if event_cache.key?(row['event_id'])
                  event_cache[row['event_id']].dup
                else
                  event = fetch_event(row['event_id'])
                  event_cache[row['event_id']] = event.dup
                  event
                end
        price = event['sheets'][row['sheet_rank']]['price']
        event.delete('sheets')
        event.delete('total')
        event.delete('remains')

        {
          id:          row['id'],
          event:       event,
          sheet_rank:  row['sheet_rank'],
          sheet_num:   row['sheet_num'],
          price:       price,
          reserved_at: row['reserved_at'].to_i,
          canceled_at: row['canceled_at']&.to_i,
        }
      end

      user['recent_reservations'] = recent_reservations

      user['total_price'] = reservation_master.select { |res| res['canceled_at'].nil? }.map { |res| res['sheet_price'] + res['event_price'] }.inject(:+)

      recent_event_ids = reservation_master.group_by { |row| row['event_id'] }.sort_by { |_, events| events.map { |e| e['canceled_at'] || e['reserved_at'] }.max }.map { |r| r[0] }.reverse.uniq.slice(0..4)
      recent_events = recent_event_ids.map do |event_id|
        event = if event_cache.key?(event_id)
                  event_cache[event_id].dup
                else
                  event = fetch_event(event_id)
                  event_cache[event_id] = event.dup
                  event
                end
        event['sheets'].each { |_, sheet| sheet.delete('detail') }
        event
      end
      user['recent_events'] = recent_events

      user.to_json
    end


    post '/api/actions/login' do
      login_name = body_params['login_name']
      password   = body_params['password']

      user      = db.xquery('SELECT * FROM users WHERE login_name = ?', login_name).first
      pass_hash = OpenSSL::Digest::SHA256.hexdigest(password)
      halt_with_error 401, 'authentication_failed' if user.nil? || pass_hash != user['pass_hash']

      session['user_id'] = user['id']

      user = get_login_user
      user.to_json
    end

    post '/api/actions/logout', login_required: true do
      session.delete('user_id')
      status 204
    end

    get '/api/events' do
      events = get_events.map(&method(:sanitize_event))
      events.to_json
    end

    get '/api/events/:id' do |event_id|
      user = get_login_user || {}
      event = get_event(event_id, user['id'])
      halt_with_error 404, 'not_found' if event.nil? || !event['public']

      event = sanitize_event(event)
      event.to_json
    end

    post '/api/events/:id/actions/reserve', login_required: true do |event_id|
      rank = body_params['sheet_rank']
      halt_with_error 400, 'invalid_rank' unless validate_rank(rank)

      user  = get_login_user
      # event = get_event(event_id, user['id'])
      event = db.xquery('SELECT * FROM events WHERE id = ? LIMIT 1', event_id).first
      halt_with_error 404, 'invalid_event' unless event && event['public_fg']

      sheet = nil
      reservation_id = nil

      reservations = db.xquery('SELECT sheet_id FROM reservations WHERE event_id = ? AND canceled_at IS NULL AND reserved_at IS NOT NULL', event['id'])
      sheets = db.xquery('SELECT * FROM sheets WHERE `rank` = ?', rank)

      remained_sheets = sheets.to_a.map {|x| x['id']} - reservations.map {|x| x['sheet_id']}

      halt_with_error 409, 'sold_out' if remained_sheets.size == 0

      remained_sheets.shuffle!

      remained_sheets.each do |sheet_id|
        sheet = sheets.find {|x| x['id'] == sheet_id}
        begin
          db.xquery('INSERT INTO reservations (event_id, sheet_id, user_id, reserved_at, event_price, sheet_rank, sheet_num, sheet_price) VALUES (?, ?, ?, ?, ?, ?, ? ,?)', event['id'], sheet['id'], user['id'], Time.now.utc.strftime('%F %T.%6N'), event['price'], sheet['rank'], sheet['num'], sheet['price'])
          reservation_id = db.last_id
          break
        rescue => e
          next
        end
      end

      status 202
      return { id: reservation_id, sheet_rank: rank, sheet_num: sheet['num'] } .to_json
    end

    delete '/api/events/:id/sheets/:rank/:num/reservation', login_required: true do |event_id, rank, num|
      user  = get_login_user
      # event = get_event(event_id, user['id'])
      event = db.xquery('SELECT * FROM events WHERE id = ? LIMIT 1', event_id).first

      halt_with_error 404, 'invalid_event' unless event && event['public_fg']
      halt_with_error 404, 'invalid_rank'  unless validate_rank(rank)

      sheet = db.xquery('SELECT * FROM sheets WHERE `rank` = ? AND num = ?', rank, num).first
      halt_with_error 404, 'invalid_sheet' unless sheet

      db.query('BEGIN')
      begin
        reservation = db.xquery('SELECT * FROM reservations WHERE event_id = ? AND sheet_id = ? AND canceled_at IS NULL FOR UPDATE', event['id'], sheet['id']).first
        unless reservation
          db.query('ROLLBACK')
          halt_with_error 400, 'not_reserved'
        end
        if reservation['user_id'] != user['id']
          db.query('ROLLBACK')
          halt_with_error 403, 'not_permitted'
        end

        db.xquery('UPDATE reservations SET canceled_at = NOW() WHERE id = ?', reservation['id'])
        db.query('COMMIT')
      rescue => e
        warn "rollback by: #{e}"
        db.query('ROLLBACK')
        halt_with_error
      end

      status 204
    end

    get '/admin/' do
      @administrator = get_login_administrator
      @events = get_events(only_public: false, need_reservasion: false) if @administrator

      erb :admin
    end

    post '/admin/api/actions/login' do
      login_name = body_params['login_name']
      password   = body_params['password']

      administrator = db.xquery('SELECT * FROM administrators WHERE login_name = ?', login_name).first
      pass_hash     = OpenSSL::Digest::SHA256.hexdigest(password)
      halt_with_error 401, 'authentication_failed' if administrator.nil? || pass_hash != administrator['pass_hash']

      session['administrator_id'] = administrator['id']

      administrator = get_login_administrator
      administrator.to_json
    end

    post '/admin/api/actions/logout', admin_login_required: true do
      session.delete('administrator_id')
      status 204
    end

    get '/admin/api/events', admin_login_required: true do
      events = get_events(only_public: false)
      events.to_json
    end

    post '/admin/api/events', admin_login_required: true do
      title  = body_params['title']
      public = body_params['public'] || false
      price  = body_params['price']

      db.query('BEGIN')
      begin
        db.xquery('INSERT INTO events (title, public_fg, closed_fg, price) VALUES (?, ?, 0, ?)', title, public, price)
        event_id = db.last_id
        db.query('COMMIT')
      rescue
        db.query('ROLLBACK')
      end

      event = get_event(event_id)
      event&.to_json
    end

    get '/admin/api/events/:id', admin_login_required: true do |event_id|
      event = get_event(event_id)
      halt_with_error 404, 'not_found' unless event

      event.to_json
    end

    post '/admin/api/events/:id/actions/edit', admin_login_required: true do |event_id|
      public = body_params['public'] || false
      closed = body_params['closed'] || false
      public = false if closed

      event = get_event(event_id)
      halt_with_error 404, 'not_found' unless event

      if event['closed']
        halt_with_error 400, 'cannot_edit_closed_event'
      elsif event['public'] && closed
        halt_with_error 400, 'cannot_close_public_event'
      end

      # db.query('BEGIN')
      # begin
      #   db.xquery('UPDATE events SET public_fg = ?, closed_fg = ? WHERE id = ?', public, closed, event['id'])
      #   db.query('COMMIT')
      # rescue
      #   db.query('ROLLBACK')
      # end

      db.xquery('UPDATE events SET public_fg = ?, closed_fg = ? WHERE id = ?', public, closed, event['id'])

      # ここでは最新の情報とするためキャッシュを削除する
      @cached_event_records = {}

      event = get_event(event_id)
      event.to_json
    end

    get '/admin/api/reports/events/:id/sales', admin_login_required: true do |event_id|
      # event = get_event(event_id)

      query = <<~SQL
        SELECT r.id,
         r.sheet_rank,
         r.sheet_num,
         r.user_id,
         DATE_FORMAT(r.reserved_at, '%Y-%m-%dT%TZ') as reserved_at,
         IF(r.canceled_at != '', DATE_FORMAT(r.canceled_at, '%Y-%m-%dT%TZ'), '') as canceled_at,
         (r.event_price + r.sheet_price) as price
         FROM reservations r WHERE r.event_id = ? ORDER BY reserved_at ASC
      SQL

      reservations = db.xquery(query, event_id)

      reports = reservations.map do |reservation|
        {
          reservation_id: reservation['id'],
          event_id:       event_id,
          rank:           reservation['sheet_rank'],
          num:            reservation['sheet_num'],
          user_id:        reservation['user_id'],
          sold_at:        reservation['reserved_at'],
          canceled_at:    reservation['canceled_at'],
          price:          reservation['price']
        }
      end

      render_report_csv(reports)
    end

    get '/admin/api/reports/sales', admin_login_required: true do
      query = <<-'EOS'
      SELECT
          r.id AS reservation_id,
          r.event_id AS event_id,
          r.sheet_rank as rank,
          r.sheet_num as num,
          (r.sheet_price + r.event_price) AS price,
          r.user_id AS user_id,
          DATE_FORMAT(reserved_at,"%Y-%m-%dT%TZ") AS sold_at,
          IF(r.canceled_at != '', DATE_FORMAT(r.canceled_at,"%Y-%m-%dT%TZ"), '') AS canceled_at
      FROM
          reservations r
      ORDER BY
          sold_at ASC
      EOS
      reports = db.query(query)

      keys = %i[reservation_id event_id rank num price user_id sold_at canceled_at]
      body = keys.join(',')
      body << "\n"
      reports.each do |report|
        body << report.values.join(',')
        body << "\n"
      end

      headers({
        'Content-Type'        => 'text/csv; charset=UTF-8',
        'Content-Disposition' => 'attachment; filename="report.csv"',
      })
      body
    end
  end
end
