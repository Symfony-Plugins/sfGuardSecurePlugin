<?php

class PluginsfGuardLoginFailure extends BasesfGuardLoginFailure
{

  public static function trackFailure($username)
  {
    $failure = new sfGuardLoginFailure();
    $failure->setUsername($username);
    $failure->setFailedAt(time());
    $failure->setCookieId(array_key_exists('HTTP_COOKIE', $_SERVER) ? $_SERVER['HTTP_COOKIE']: null);
    $failure->setIpAddress(array_key_exists('REMOTE_ADDR', $_SERVER)? $_SERVER['REMOTE_ADDR']: null);
    $failure->save();
  }
}
