<?php

class sfGuardFormSignin extends sfGuardSecureFormSignin
{
  public function configure()
  {
	parent::configure();

    $this->setWidget('username', new sfWidgetFormInput());
    $this->setWidget('password', new sfWidgetFormInput(array('type' => 'password')));

    $this->setValidator('username', new sfValidatorString());
    $this->setValidator('password', new sfValidatorString());

    if ( sfConfig::get('app_sf_guard_secure_plugin_enable_remember_cookie',0))
    {
      $this->setWidget('remember', new sfWidgetFormInputCheckbox());
      $this->setValidator('remember', new sfValidatorBoolean());
    }
    
    

    $this->validatorSchema->setPostValidator(new sfGuardValidatorUser());

    $this->widgetSchema->setNameFormat('signin[%s]');
    $this->validatorSchema->setOption('allow_extra_fields', true); 
	  if ( isset ($this['captcha']) )
    {
      
      $this->getWidgetSchema()->moveField('captcha', 'after', 'password');
      $this->validatorSchema->setOption('allow_extra_fields', true); 
    }

  }
}
