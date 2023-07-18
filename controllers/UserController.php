<?php
require_once "models/User.php";
require_once "controllers/BaseController.php";
require_once "controllers/Validator.php";
require_once "controllers/Upload.php";
class UserController extends BaseController
{
    var $mod_user;
    function __construct(){
        $this->mod_user=new User();
    }
    public function login(){
        if(isset($_SESSION['is_logged_in'])){
            $this->redirect('index.php?mod=article&act=index');
        }   
        else $this->view('auth/login.php');
            
    }
    public function register(){
        if(isset($_SESSION['is_logged_in'])){
            $this->redirect('index.php?mod=article&act=index');
        }
        else $this->view('auth/register.php');
    }
    public function authenticate() {
        if(isset($_SESSION['is_logged_in'])){
            $this->redirect('index.php?mod=article&act=index');
        }
        else{
           $data = $_POST;
            $rules = [
                'email' => 'email|required',
                'password' => 'required',
            ];
            $messages = [
                'email' => [
                    'required' => 'Email không được để trống',
                    'email' => 'Email không đúng định dạng',
                ],
                'password' => [
                    'required' => 'Mật khẩu không được để trống',
                ],
            ];
            $validator = new Validator($data, $rules, $messages);
            $errors = $validator->validate();
            $errorMessages = [];
            if (!empty($errors)) {
                foreach ($errors as $field => $fieldErrors) {
                    foreach ($fieldErrors as $error) {
                        $errorMessages[$field] = $error;
                    }
                }
                $_SESSION['errorMessages'] = $errorMessages;
                $this->redirect('back');
            } else {
                $email = $data['email'];
                $user = $this->mod_user->checkLogin($email);
                if($user && password_verify($data['password'], $user['password']) ){
                    {
                        if (isset($data['remember_me'])) {
                            $rememberMeToken = base64_encode(random_bytes(64));
                            setcookie('remember_me_token', $rememberMeToken, time() + 60*60*24*30);
                            $this->mod_user->saveToken($email,$rememberMeToken);
                        }
                        else{
                            $rememberMeToken = base64_encode(random_bytes(64));
                            setcookie('remember_me_token', $rememberMeToken, time() + 60*60*24);
                            $this->mod_user->saveToken($email,$rememberMeToken);
                        }
                        $_SESSION['is_logged_in'] = true;
                        $_SESSION['user_data'] = array(
                            "id" => $user['id'],
                            "name" => $user['name'],
                            "email" => $user['email'] 
                        );
                        setcookie('msg','Chúc mừng bạn đã đăng nhập thành công',time()+2);
                        $this->redirect('index.php?mod=article&act=index');
                    }
        
                } 
                else 
                {
                    $_SESSION['errorMessages']['email'] = 'Tài khoản hoặc mật khẩu không chính xác';
                    $this->redirect('back');
                }
            } 
        }
    }
    public function store(){
        if(isset($_SESSION['is_logged_in'])){
            $this->redirect('index.php?mod=article&act=index');
        }
        else{
            $data = $_POST;
            $rules = [
                'name' => 'max:255|special_characters|required',
                'email' => 'max:255|email|unique|required',
                'password' => 'min:6|max:255|required',
            ];
            $messages = [
                'name' => [
                    'required' => 'Tên không được để trống',
                    'special_characters' => 'Tên không được có ký tự đặc biệt',
                    'max' => 'Tên không quá 255 ký tự',
                ],
                'email' => [
                    'required' => 'Email không được để trống',
                    'email' => 'Email không đúng định dạng',
                    'unique' => 'Email đã tồn tại',
                    'max' => 'Email không quá 255 ký tự',
                ],
                'password' => [
                    'required' => 'Mật khẩu không được để trống',
                    'min' => 'Mật khẩu tối thiểu 6 ký tự',
                    'max' => 'Mật khẩu không quá 255 ký tự',
                ],
            ];
            $validator = new Validator($data, $rules, $messages);
            $errors = $validator->validate();
            $errorMessages = [];
            if (!empty($errors)) {
                foreach ($errors as $field => $fieldErrors) {
                    foreach ($fieldErrors as $error) {
                        $errorMessages[$field] = $error;
                    }
                }
                $_SESSION['errorMessages'] = $errorMessages;
                $this->redirect('back');
            } else {
                $data['password'] = password_hash($data['password'], PASSWORD_DEFAULT);
                $status = $this->mod_user->store($data);
                if($status) setcookie('msg','Đăng ký tài khoản thành công',time()+2);
                    else setcookie('msgf','Thêm mới thất bại',time()+2);
                $this->redirect('index.php?mod=user&act=login');
            }
        }
    }
    public function logout(){
        unset($_SESSION['is_logged_in']);
        unset($_SESSION['user_data']);
        setcookie('remember_me_token','', time() - 3600);
        setcookie('msg','Bạn đã đăng xuất khỏi hệ thống',time()+1);
        $this->redirect('index.php?mod=article&act=index');
	}
}
?>