<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Validates a user login.
 * 
 * @package    symfony
 * @subpackage plugin
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id: sfGuardValidatorUser.class.php 30261 2010-07-16 14:06:36Z fabien $
 */
class sfGuardValidatorUser extends sfValidatorBase
{
  /**
   * Configures the user validator.
   * 
   * Available options:
   * 
   *  * username_field      Field name of username field (username by default)
   *  * password_field      Field name of password field (password by default)
   *  * throw_global_error  Throws a global error if true (false by default)
   * 
   * @see sfValidatorBase
   */
  public function configure($options = array(), $messages = array())
  {
    $this->addOption('username_field', 'username');
    $this->addOption('password_field', 'password');
    $this->addOption('throw_global_error', false);
    $this->addOption('check_login_failure', true);

    $this->setMessage('invalid', 'The username and/or password is invalid.');
  }

  /**
   * @see sfValidatorBase
   */
  protected function doClean($values)
  {
    // only validate if username and password are both present
    if (isset($values[$this->getOption('username_field')]) && isset($values[$this->getOption('password_field')]))
    {
      $username = $values[$this->getOption('username_field')];
      $password = $values[$this->getOption('password_field')];
	    $session_user = sfContext::getInstance()->getUser();

      // user exists?
      if ($user = sfGuardUserPeer::retrieveByUsername($username))
      {
        // password is ok?
        if ($user->getIsActive() && $user->checkPassword($password))
        {
          /* Added for sfGuardSecurity */
          $this->checkForceRedirectPasswordChange($user);
          $session_user->setAttribute('sf_guard_secure_plugin_login_failure_detected', 0);
          /* end */
          return array_merge($values, array('user' => $user));
        }
      }


      if ($this->getOption('check_login_failure'))
      {
        /* Added for sfGuardSecurity */
        sfGuardLoginFailure::trackFailure($username);
        $this->checkSecurityAttack($username);
        /* end */
      }


      if ($this->getOption('throw_global_error'))
      {
        throw new sfValidatorError($this, 'invalid');
      }

      throw new sfValidatorErrorSchema($this, array(
        $this->getOption('username_field') => new sfValidatorError($this, 'invalid'),
      ));
    }

    // assume a required error has already been thrown, skip validation
    return $values;
  }

  private function checkSecurityAttack($username)
  {
    $login_failure_max_attempts_per_user = sfConfig::get('app_sf_guard_secure_plugin_login_failure_max_attempts_per_user', 3);
    $login_failure_max_attempts_per_ip   = sfConfig::get('app_sf_guard_secure_plugin_login_failure_max_attempts_per_ip', 10);    
    $login_failure_time_window           = sfConfig::get('app_sf_guard_secure_plugin_login_failure_time_window', 90); 
  
    $failures_for_username = sfGuardLoginFailurePeer::doCountForUsernameInTimeWindow($username, $login_failure_time_window*60);
    $failures_for_ip   = sfGuardLoginFailurePeer::doCountForIpInTimeWindow($_SERVER['REMOTE_ADDR'] , $login_failure_time_window*60 );

    $user = sfContext::getInstance()->getUser();

    if(($failures_for_username > $login_failure_max_attempts_per_user ) || ($failures_for_ip > $login_failure_max_attempts_per_ip))
    {
      $user->setAttribute('sf_guard_secure_plugin_login_failure_detected', 1);
    }
  }

  private function checkForceRedirectPasswordChange($user)
  {
    $time_window      = sfConfig::get('app_sf_guard_secure_plugin_force_change_password_after', 30);
    $now = time();
    $change_password_at = $user->getChangePasswordAt('U');
    $change_password_at = is_null($change_password_at)? $user->getLastLogin('U'):$change_password_at;
    $change_password_at = is_null($change_password_at)? $user->getCreatedAt('U'):$change_password_at;
    if ( !is_null($change_password_at) )
    {
      $days = (($now - $change_password_at)/60/60/24);
      if ( $days > $time_window )
      {
        $user->setMustChangePassword(true);
        $user->save();
      }
    }
  }


}
