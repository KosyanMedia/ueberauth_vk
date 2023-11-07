defmodule Ueberauth.Strategy.VK do
  @moduledoc """
  VK Strategy for Überauth.
  """

  use Ueberauth.Strategy, default_scope: "",
                          default_display: "page",
                          profile_fields: "",
                          uid_field: :id,
                          allowed_request_params: [
                            :display,
                            :scope
                          ],
                          api_version: "5.122",
                          ignores_csrf_attack: true # to support ueberauth v0.10 in guestia

  alias OAuth2.{Response, Error, Client}
  alias Ueberauth.Auth.{Info, Credentials, Extra}
  alias Ueberauth.Strategy.VK.OAuth

  @doc """
  Handles initial request for VK authentication.
  """
  def handle_request!(conn) do
    allowed_params =
      conn
      |> option(:allowed_request_params)
      |> Enum.map(&to_string/1)

    authorize_url =
      conn.params
      |> maybe_replace_param(conn, "auth_type", :auth_type)
      |> maybe_replace_param(conn, "scope", :default_scope)
      |> maybe_replace_param(conn, "display", :default_display)
      |> Enum.filter(fn {k, _} -> Enum.member?(allowed_params, k) end)
      |> Enum.map(fn {k, v} -> {String.to_existing_atom(k), v} end)
      |> Keyword.put(:redirect_uri, callback_url(conn))
      |> OAuth.authorize_url!


    redirect!(conn, authorize_url)
  end

  @doc """
  Handles the callback from VK.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: callback_url(conn)]
    client = OAuth.get_token!([code: code], opts)
    token = client.token

    if token.access_token == nil do
      err = token.other_params["error"]
      desc = token.other_params["error_description"]
      set_errors!(conn, [error(err, desc)])
    else
      fetch_user(conn, client)
    end
  end

  @doc """
  Handles the callback from app with access_token.
  """
  def handle_callback!(%Plug.Conn{params: %{"access_token" => access_token}} = conn) do
    client = OAuth.client
    token = OAuth2.AccessToken.new(access_token)
    verified_token = check_access_token(conn, client, token)

    if verified_token do
      other_params = Map.put(token.other_params, "user_id", verified_token["user_id"])
      token = Map.put(token, :other_params, other_params)
      put_private(conn, :vk_token, token)
      fetch_user(conn, %{client | token: token})
    else
      set_errors!(conn, [error("token", "Token verification failed")])
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:vk_user, nil)
    |> put_private(:vk_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.vk_user[uid_field]
  end

  @doc """
  Includes the credentials from the VK response.
  """
  def credentials(conn) do
    token = conn.private.vk_token
    scopes = String.split(
      token.other_params["scope"] || "", ","
    )

    %Credentials{
      expires: token.expires_at == nil,
      expires_at: token.expires_at,
      scopes: scopes,
      token: token.access_token
    }
  end

  @doc """
  Fetches the fields to populate the info section of the
  `Ueberauth.Auth` struct.
  """
  def info(conn) do
    token = conn.private.vk_token
    user = conn.private.vk_user

    %Info{
      first_name: user["first_name"],
      last_name: user["last_name"],
      email: token.other_params["email"],
      name: fetch_name(user),
      image: fetch_image(user),
      location: user["city"],
      description: user["about"],
      urls: %{
        vk: "https://vk.com/id" <> to_string(user["id"])
      }
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from
  the vk callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.vk_token,
        user: conn.private.vk_user
      }
    }
  end

  defp fetch_name(user), do: user["first_name"] <> " " <> user["last_name"]

  defp fetch_image(user) do
    user_photo =
      user
      |> Enum.filter(fn {k, _v} -> String.starts_with?(k, "photo_") end)
      |> Enum.sort_by(fn {"photo_" <> size, _v} -> Integer.parse(size) end)
      |> List.last

    case user_photo do
      nil -> nil
      {_, photo_url} -> photo_url
    end
  end

  defp fetch_user(conn, client) do
    conn = put_private(conn, :vk_token, client.token)
    path = user_query(conn)

    case Client.get(client, path) do
      {:ok, %Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %Response{status_code: status_code, body: user}}
        when status_code in 200..399 ->
          users = user["response"]
          if users do
            put_private(conn, :vk_user, List.first(users))
          else
            code = user["error"]["error_code"]
            msg = user["error"]["error_msg"]
            set_errors!(conn, [error("OAuth request error", "code: #{code}; msg: #{msg}")])
          end
      {:error, %Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp user_query(conn) do
    query =
      conn
      |> query_params(:locale)
      |> Map.merge(query_params(conn, :profile))
      |> Map.merge(query_params(conn, :user_id))
      |> Map.merge(query_params(conn, :access_token))
      |> Map.merge(query_params(conn, :api_version))
      |> URI.encode_query
    "https://api.vk.com/method/users.get?#{query}"
  end

  defp query_params(conn, :profile) do
    case option(conn, :profile_fields) do
      nil -> %{}
      fields -> %{"fields" => fields}
    end
  end
  defp query_params(conn, :locale) do
    case option(conn, :locale) do
      nil -> %{}
      locale -> %{"lang" => locale}
    end
  end
  defp query_params(conn, :api_version) do
    case option(conn, :api_version) do
      nil -> %{}
      api_version -> %{"v" => api_version}
    end
  end
  defp query_params(conn, :user_id) do
    %{"user_ids" => conn.private.vk_token.other_params["user_id"]}
  end
  defp query_params(conn, :access_token) do
    %{"access_token" => conn.private.vk_token.access_token}
  end

  defp option(conn, key) do
    default = Keyword.get(default_options(), key)

    conn
    |> options
    |> Keyword.get(key, default)
  end
  defp option(nil, conn, key), do: option(conn, key)
  defp option(value, _conn, _key), do: value

  defp maybe_replace_param(params, conn, name, config_key) do
    if params[name] do
      params
    else
      Map.put(params, name, option(params[name], conn, config_key))
    end
  end

  def check_access_token(conn, client, token) do
    config = Application.get_env(:ueberauth, OAuth)
    params = %{
      "token" => token.access_token,
      "access_token" => config[:client_service_key],
      "v" => option(conn, :api_version)
    }
    case OAuth2.Client.get(client, "/secure.checkToken", [], params: params) do
      {:ok, %OAuth2.Response{
        status_code: 200,
        body: data
      }} -> data["response"]
      data -> false
    end
  end
end
