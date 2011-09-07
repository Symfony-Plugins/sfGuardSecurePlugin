<?php

class sfGuardFormSignin extends sfGuardSecureFormSignin
{
  public function configure()
  {
	parent::configure();

    $this->setWidget('username', new sfWidgetFormInput());
    $this->setWidget('password', new sfWidgetFormInput(array('type' => 'password')));
    $this->setWidget('remember', new sfWidgetFormInputCheckbox());

    $this->setValidator('username', new sfValidatorString());
    $this->setValidator('password', new sfValidatorString());
    $this->setValidator('remember', new sfValidatorBoolean());

    $this->validatorSchema->setPostValidator(new sfGuardValidatorUser());

    $this->widgetSchema->setNameFormat('signin[%s]');

	  if ( isset ($this['captcha']) )
    {
      $this->getWidgetSchema()->moveField('captcha', 'after', 'password');
    }

  }
}
