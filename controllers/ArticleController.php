<?php
require_once "models/Article.php";
require_once "controllers/BaseController.php";
require_once "controllers/Validator.php";
require_once "controllers/Upload.php";
class ArticleController extends BaseController
    {
        var $mod_article;
        function __construct(){
            $this->mod_article=new Article();
        }
        public function index(){
            $articles = $this->mod_article->getList();
            $this->view('crud/crud-list.php', [
                'articles' => $articles,
            ]);
        }

        public function create(){
            $this->view('crud/crud-add.php');
        }
        public function store(){
            $data = $_POST;
            $thumbnail="";
            $target_dir="views/assets/images/thumbnail/";
            $upload = uploadFile('thumbnail' ,$target_dir , array ('jpg', 'jpeg', 'png', 'gif', 'webp'), 2);
            $rules = [
                'title' => 'special_characters|max:120|required',
                'author' => 'special_characters|required',
                'description' => 'special_characters|required',
            ];
            $messages = [
                'title' => [
                    'required' => 'Tiêu đề không được để trống',
                    'max' => 'Tiêu đề không quá 120 ký tự',
                    'special_characters' => 'Tiêu đề không có ký tự đặc biệt',
                ],
                'author' => [
                    'required' => 'Tác giả không được để trống',
                    'special_characters' => 'Tác giả không có ký tự đặc biệt',
                ],
                'description' => [
                    'required' => 'Mô tả không được để trống',
                    'special_characters' => 'Mô tả không có ký tự đặc biệt',
                ],
            ];
            $validator = new Validator($data, $rules, $messages);
            $errors = $validator->validate();
            $errorMessages = [];
            if (!empty($errors) || !$upload[0]) {
                foreach ($errors as $field => $fieldErrors) {
                    foreach ($fieldErrors as $error) {
                        $errorMessages[$field] = $error;
                    }
                }
                $_SESSION['upload_status'] = $upload;
                $_SESSION['errorMessages'] = $errorMessages;
                $this->redirect('back');
            } else {
                move_uploaded_file($_FILES['thumbnail']["tmp_name"], $upload[1]);
                $data['thumbnail']= $upload[1];
                $data['date'] = date("Y-m-d H:i:s");
                $status = $this->mod_article->store($data);
                if($status) setcookie('msg','Thêm mới thành công',time()+2);
                    else setcookie('msgf','Thêm mới thất bại',time()+2);
                $this->redirect('index.php?mod=article&act=index');
            }
            
        }
        public function edit(){
            $id = $_GET['id'];
            $article = $this->mod_article->find($id);
            $this->view('crud/crud-edit.php',[
                'article' => $article,
            ]);
        }
        public function update(){
            $id = $_POST['id'];
            $data = $_POST;
            $rules = [
                'title' => 'required',
                'author' => 'required',
                'description' => 'max:255|required',
            ];
            $messages = [
                'title' => [
                    'required' => 'Tiêu đề không được để trống',
                    'max' => 'Tiêu đề không quá 60 từ'
                ],
                'author' => [
                    'required' => 'Tác giả không được để trống',
                ],
                'description' => [
                    'required' => 'Mô tả không được để trống',
                    'max' => 'Mô tả không quá 255 từ'
                ],
            ];

            $validator = new Validator($data, $rules, $messages);
            $errors = $validator->validate();
            $errorMessages = [];
            $upload = array();
            if($_FILES['thumbnail']['name']){
                $target_dir="views/assets/images/thumbnail/";
                $upload = uploadFile('thumbnail' ,$target_dir , array ('jpg', 'jpeg', 'png', 'gif', 'webp'), 2);
            }
            else{
                $data['thumbnail'] = $this->mod_article->getCurrentThumbnail($id);
                $upload[0] = true; 
            }
            if (!empty($errors) || !($upload[0])) {
                foreach ($errors as $field => $fieldErrors) {
                    foreach ($fieldErrors as $error) {
                        $errorMessages[$field] = $error;
                    }
                }
                $_SESSION['upload_status'] = $upload;
                $_SESSION['errorMessages'] = $errorMessages;
                $this->redirect('back');
            } else {
                if($_FILES['thumbnail']['name']){
                    $old_thumbnail = $this->mod_article->getCurrentThumbnail($id);
                    unlink($old_thumbnail);
                    move_uploaded_file($_FILES['thumbnail']["tmp_name"], $upload[1]);
                    $data['thumbnail'] = $upload[1];
                }
                $data['update_at'] = date("Y-m-d H:i:s");
                $status = $this->mod_article->edit($data,$id);
                if($status) setcookie('msg','Cập nhật thành công',time()+2);
                else setcookie('msgf','Cập nhật thất bại',time()+2);
                $this->redirect('index.php?mod=article&act=index');
            }
            
        }
        public function delete(){
            $id = $_GET['id'];
            $thumbnail = $this->mod_article->getCurrentThumbnail($id);
            unlink($thumbnail);
            $status=$this->mod_article->destroy($id);
            if($status) setcookie('msg','Xoá thành công',time()+2);
            else setcookie('msgf','Xoá thất bại',time()+2);
            $this->redirect('index.php?mod=article&act=index');
        }
    }
?>