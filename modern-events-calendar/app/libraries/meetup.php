<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC meetup class.
 * @author Webnus <info@webnus.net>
 */
class MEC_meetup extends MEC_base
{
    /**
     * @var MEC_main
     */
    private $main;

    public function __construct()
    {
        $this->main = $this->getMain();
    }

    /**
     * @return string
     */
    public function get_redirect_url(): string
    {
        return $this->main->URL('backend').'admin.php?page=MEC-ix&tab=MEC-meetup-import&mec-ix-action=meetup-import-start';
    }

    public function get_token()
    {
        // Get MEC IX options
        $ix = $this->main->get_ix_options();

        // Refresh Token
        $refresh_token = $ix['meetup_refresh_token'] ?? '';

        $response = wp_remote_post('https://secure.meetup.com/oauth2/access', [
            'body' => [
                'client_id' => $ix['meetup_public_key'] ?? '',
                'client_secret' => $ix['meetup_secret_key'] ?? '',
                'grant_type' => 'refresh_token',
                'refresh_token' => $refresh_token
            ],
        ]);

        // Error Happened
        if(is_wp_error($response)) return '';

        // Response Body
        $body = json_decode(wp_remote_retrieve_body($response));

        return $body->access_token ?? '';
    }

    public function get_tokens_by_code(string $code = '')
    {
        // Get MEC IX options
        $ix = $this->main->get_ix_options();

        $response = wp_remote_post('https://secure.meetup.com/oauth2/access', [
            'body' => [
                'client_id' => $ix['meetup_public_key'] ?? '',
                'client_secret' => $ix['meetup_secret_key'] ?? '',
                'grant_type' => 'authorization_code',
                'redirect_uri' => $this->get_redirect_url(),
                'code' => $code,
            ],
        ]);

        // Error Happened
        if(is_wp_error($response)) return '';

        // Response Body
        $body = json_decode(wp_remote_retrieve_body($response));

        $token = $body->access_token ?? '';
        $refresh = $body->refresh_token ?? '';

        $this->main->save_ix_options([
            'meetup_refresh_token' => $refresh
        ]);

        return $token;
    }

    /**
     * Get Meetup Event by id.
     *
     * @return array
     */
    public function get_event($token, $event_id = 0)
    {
        $query = 'query ($event_id: ID!) {
            event(id: $event_id) {
                id
                title
                dateTime
                endTime
                description
                shortDescription
                recurrenceDescription
                duration
                timezone
                eventUrl
                status
                venue {
                    id
                    name
                    address
                    city
                    state
                    country
                    lat
                    lng
                    postalCode
                    zoom
                }
                onlineVenue {
                    type
                    url
                }
                isOnline
                imageUrl
                series {
                    weeklyRecurrence {
                        weeklyInterval
                        weeklyDaysOfWeek
                    }
                    monthlyRecurrence {
                        monthlyWeekOfMonth
                        monthlyDayOfWeek
                    }
                    endDate
                    description
                }
                feeSettings {
                    amount
                    currency
                }
                hosts {
                    id
                    name
                    email
                    lat
                    lon
                    city
                    state
                    country
                }
                group {
                    id
                    name
                    description
                    emailListAddress
                    urlname
                    logo {
                        baseUrl
                    }
                }
            }
        }';

        $variables = ['event_id' => $event_id];
        return $this->query($token, $query, $variables);
    }

    /**
     * Get Meetup Events By Group ID With pagination
     *
     * @return array Group ID
     */
    public function get_group_events($token, $meetup_group_id = '')
    {
        $query = 'query ($urlname: String!, $items_num: Int!) {
            groupByUrlname(urlname: $urlname) {
                id
                name
                upcomingEvents(input: {first: $items_num}) {
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                    count
                    edges {
                        node {
                            id
                            token
                            title
                            eventUrl
                            dateTime
                            endTime
                        }
                    }
                }
            }
        }';
        $variables = ['urlname' => $meetup_group_id, 'items_num' => 999];
        return $this->query($token, $query, $variables);
    }

    /**
     * Get Meetup Authorized User Data
     *
     * @return array
     */
    public function get_group_name($token, $meetup_group_id)
    {
        $query = '
        query ($urlname: String!) {
            groupByUrlname(urlname: $urlname) {
                id
                name
            }
        }';

        $variables = ['urlname' => $meetup_group_id];
        return $this->query($token, $query, $variables);
    }

    public function query(string $token, string $query, array $variables = [])
    {
        $headers = ['Content-Type: application/json'];
        $headers[] = 'Authorization: Bearer ' . $token;

        $data = @file_get_contents(
            'https://api.meetup.com/gql',
            false,
            stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => $headers,
                    'content' => json_encode(['query' => $query, 'variables' => $variables]),
                ]
            ])
        );

        // No Data
        if($data === false) return [];

        return json_decode($data, true);
    }
}
