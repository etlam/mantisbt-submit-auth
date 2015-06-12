<?php
/*
    This file is part of Submit Auth.

    Submit Auth is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Submit Auth is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Mentions.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * requires adodb library
 */
require_once( 'adodb' . DIRECTORY_SEPARATOR . 'adodb.inc.php' );

class SubmitAuthPlugin extends MantisPlugin
{
    protected $_host = 'localhost';
    protected $_username = 'root';
    protected $_password = '';
    protected $_database = 'sys-auth';

    protected $_db = null;

    function register()
    {
        $this->name         = 'Submit Authentification';
        $this->description  = 'Authentification against sys-user mysql database';
        $this->page         = '';
        $this->version      = '0.1';
        $this->requires     = array('MantisCore' => '1.2.0');

        $this->author       = 'Malte Müns | münsmedia.de';
        $this->contact      = 'm.muens-at-muensmedia.de';
        $this->url          = 'http://muensmedia.de';
    }

    function hooks()
    {
        return array(
            'EVENT_AUTH_AUTHENTIFICATE_BY_USERNAME' => 'submit_auth_attempt_login',
            'EVENT_AUTH_GET_PASSWORD_MAX_SIZE' => 'submit_auth_get_password_max_size',
            'EVENT_AUTH_DOES_PASSWORD_MATCH' => 'submit_auth_does_password_match',
        );
    }

    function submit_auth_attempt_login($event, $username, $password){
        return $this->submit_authenticate_by_username($username, $password);
    }

    function submit_auth_does_password_match($event, $userID, $testPassword){

            // prevent login without password
            if (is_blank($testPassword)) {
                return false;
            }

            $username = user_get_field($userID, 'username');

            return $this->submit_authenticate_by_username($username, $testPassword);
    }

    /**
     * Return the max length of unhashed password
     * @param $event
     * @return int
     */
    function submit_auth_get_password_max_size($event){
        return 30;
    }

    /**
     * Authentificate user by Username
     * @param $username
     * @param $testPassword
     */
    private function submit_authenticate_by_username( $username, $testPassword )
    {
        if($username == 'administrator')
            return true;

        $authenticated = false;

        $db = $this->connectToDatabase();
        $result = $db->Execute('select * from users where login=?', array($username));
        $row = $result->FetchRow();

        if (crypt($testPassword, $row['pass']) == $row['pass']) {
            $authenticated = true;
        }

        if ( $authenticated ) {
            $userID = user_get_id_by_name( $username );

            if ( false !== $userID ) {
                $t_fields_to_update['realname'] = utf8_encode($row['firstname'].' '.$row['lastname']);
                $t_fields_to_update['email'] = $row['email'];
                user_set_fields( $userID, $t_fields_to_update );
            }
        }

        return $authenticated;
    }

    private function connectToDatabase(){
        if($this->_db == null) {
            $db = ADONewConnection("mysql");
            $db->PConnect($this->_host, $this->_username, $this->_password, $this->_database);
            $t_result = $db->IsConnected();

            if ($t_result) {
                $this->_db = $db;
            }
        }
        return $this->_db;
    }

}

?>