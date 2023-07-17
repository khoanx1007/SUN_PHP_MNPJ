<?php   
    require_once "models/User.php";
    class Validator {
        private $data;
        private $rules;
        private $messages;
        private $attributes;
        private $errors = [];

        public function __construct($data, $rules, $messages = [], $attributes = []) {
            $this->data = $data;
            $this->rules = $rules;
            $this->messages = $messages;
            $this->attributes = $attributes;
        }

        public function validate() {
            foreach ($this->rules as $field => $rule) {
                $rules = explode('|', $rule);

                foreach ($rules as $singleRule) {
                    $this->applyRule($field, $singleRule);
                }
            }
            return $this->errors;
        }

        private function applyRule($field, $rule) {
            $value = $this->data[$field];

            if ($rule === 'required' && empty($value)) {
                $this->addError($field, 'required');
            }

            else if (strpos($rule, 'max:') !== false) {
                $maxLength = explode(':', $rule)[1];
                $wordCount = str_word_count($value);
                if ($wordCount > $maxLength) {
                    $this->addError($field, 'max');
                }
            }
            else if (strpos($rule, 'min:') !== false) {
                $minLength = explode(':', $rule)[1];
                if (strlen($value) < $minLength) {
                    $this->addError($field, 'min');
                }
            }
            
            else if ($rule === 'email') {
                if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    $this->addError($field, 'email');
                }
            }
            else if ($rule === 'unique') {
                $mod_user = new User();
                $isDuplicate = $mod_user->isEmailDuplicate($mod_user->table, $value);
                if ($isDuplicate) {
                    $this->addError($field, 'unique');
                }
            }
            else if ($rule === 'special_characters') {
                if (preg_match('/[@#$%^&*():{}|<>]/', $value)) {
                    $this->addError($field, 'special_characters');
                }
            }
            
            
        }

        private function addError($field, $rule) {
            if (isset($this->messages[$field][$rule])) {
                $errorMessage = $this->messages[$field][$rule];
            }
            $this->errors[$field][] = $errorMessage;
        }

        private function getAttribute($field) {
            if (isset($this->attributes[$field])) {
                return $this->attributes[$field];
            }
            return ucfirst($field);
        }
    }
?>