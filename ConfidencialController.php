<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\DB;
use App\Models\CadenaSecreta;
use App\Models\UsuarioPrivado;
use App\Models\Credenciales;
use Illuminate\Support\Facades\Hash;
use Illuminate\Database\QueryException;

class ConfidencialController extends Controller
{
    //Se encarga de manejar el inicio de sesion
    public function login(Request $request)
    {
        if($request->has('correo') &&
        $request->has('contrasenia')){
            $correo=$request['correo'];
            $contrasenia=$request['contrasenia'];
            
            if(ConfidencialController::comprobarValidez($correo,$contrasenia)){
                $usuarioId=DB::table('credenciales')->where('correo','=',$correo)->get()->pluck('usuarioId');
                $credencial= array('contrasenia'=>$contrasenia,
                'correo'=>$correo,
                'usuarioId'=>$usuarioId[0]);

                return array(
                    '_error'=>'Ninguno',
                    'login'=>$credencial
                );

            }else{
                 $credencial= array('contrasenia'=>'',
                 'correo'=>'',
                 'usuarioId'=>''
                );   
                return array(
                    '_error'=>'Rechazado',
                    'login'=>$credencial
                );
            }
        }
        
        else{
            $credencial= array('contrasenia'=>'',
            'correo'=>'',
            'usuarioId'=>''
           );   
           return array(
               '_error'=>'Datos faltantes',
               'login'=>$credencial
           );


        }



        

        
        
        $error='Detected';
        return array('_error'=>$contraseniaConHash,
        'login'=>$credencial,
        'bcrypt'=>$bcrypt);
        
    }

    //Se encarga de registrar nuevo usuario
    public function registro(Request $request)
    {
        if($request->has('nombre') &&
        $request->has('apellidos') &&
        $request->has('correo') &&
        $request->has('contrasenia') &&
        $request->has('sexo') &&
        $request->has('fechaNacimiento')){
            $correo=$request['correo'];
            $contraseniaHash=Hash::make($request['contrasenia']);
            $id=DB::table('usuario_privados')->insertGetId([
                    'nombre'=>$request['nombre'],
                    'apellidos'=>$request['apellidos'],
                    'correo'=>$correo,
                    'contrasenia'=>$contraseniaHash,
                    'sexo'=>$request['sexo'],
                    'fechaNacimiento'=>$request['fechaNacimiento'],
            ]);
            $credencial=array('correo'=>$correo,
            'contrasenia'=>$contraseniaHash,
            'usuarioId'=>$id);


            DB::table('credenciales')->insert($credencial);  
            
            $registroResultado=array('nombre'=>$request['nombre'],
                                    'apellidos'=>$request['apellidos'],
                                    'correo'=>$request['correo'],
                                    'contrasenia'=>$request['contrasenia'],
                                    'sexo'=>$request['sexo'],
                                    'fechaNacimiento'=>$request['fechaNacimiento']);



            $error='Ninguno';

            return array('_error'=>$error,
                        'registro'=>$registroResultado,
                        'credenciales'=>$credencial);
        }
        else{
            $error='Se necesita más información';
            $registroResultado=array('nombre'=>$request['nombre'],
                                    'apellidos'=>$request['apellidos'],
                                    'correo'=>$request['correo'],
                                    'contrasenia'=>$request['contrasenia'],//nombre temporal
                                    'sexo'=>$request['sexo'],
                                    'fechaNacimiento'=>$request['fechaNacimiento']);
            $credencial=array('correo'=>'',
                            'contrasenia'=>'',//nombre temporal
                            'usuarioId'=>''); 
          
        return array('_error'=>$error,
        'registro'=>$registroResultado,
        'credenciales'=>$credencial
        );
        }
        
        
        

    }

    //Se encarga de registrar nuevo usuario
    public function guardarSecreto(Request $request)
    {
        if($request->has('correo') &&
        $request->has('contrasenia') &&
        $request->has('usuarioId') &&
        $request->has('nombre') &&
        $request->has('descripcion') &&
        $request->has('cadenaSecreta')){
            $correo=$request['correo'];
            $contrasenia=$request['contrasenia'];
            $nombre=$request['nombre'];
            $descripcion=$request['descripcion'];
            $cadenaSecreta=$request['cadenaSecreta'];
            $usuarioId=$request['usuarioId'];
            if(ConfidencialController::comprobarValidez($correo,$contrasenia)){
                DB::table('cadena_secretas')->insert([
                    'nombre'=>$nombre,
                    'descripcion'=>$descripcion,
                    'secreto'=>Crypt::encryptString($cadenaSecreta),
                    'usuarioId'=>$usuarioId
                ]);
                $error='Se agregó correctamente';    
                $secretModel=array('nombre'=>$nombre,
                'descripcion'=>$descripcion,
                'cadenaSecreta'=>$cadenaSecreta
                );
                return array('_error'=>$error,
                            'secreto'=>$secretModel);
            }
            else{
                $error='Intruso detectado';    
                $secretModel=array('nombre'=>'',
                'descripcion'=>'',
                'cadenaSecreta'=>''
                );
                return array('_error'=>$error,
                            'secreto'=>$secretModel);

            }
        }
        else{
            $error='Se necesita más información';
            $secretModel=array('nombre'=>'',
                'descripcion'=>'',
                'cadenaSecreta'=>''
                );
                return array('_error'=>$error,
                            'secreto'=>$secretModel);
        }   
    }

    //Se encarga de leer los registros
    public function leerSecretos(Request $request)
    {
        if($request->has('correo') &&
        $request->has('contrasenia') &&
        $request->has('usuarioId')){
            $correo=$request['correo'];
            $contrasenia=$request['contrasenia'];
            $usuarioId=$request['usuarioId'];
            if(ConfidencialController::comprobarValidez($correo,$contrasenia)){
                $secretosSinDescifrar=DB::table('cadena_secretas')->where('usuarioId','=',$usuarioId)->get();
                $secretosDescifrados=array();
               foreach($secretosSinDescifrar as $secretoInstancia){
                    try {
                        $secretoDescifrado= Crypt::decryptString($secretoInstancia->secreto);
                    } catch (DecryptException $e) {
                        $secretoDescifrado='';
                    }
                    $secretoInstancia->secreto=$secretoDescifrado;
                    array_push($secretosDescifrados,$secretoInstancia);
                }
                return $secretosDescifrados;
            }
            else{
                return [];
            }
        }
        else{
            return [];
        }    
        /*
        
        $nombre=Crypt::encryptString('Pizza Hawaiana');
        try {
            $decrypted = Crypt::decryptString($nombre);
        } catch (DecryptException $e) {
            //
        }
        */

    }

    private function comprobarValidez(String $correo, String $contrasenia){
        try{
        $contraseniaConHash= DB::table('credenciales')->where('correo','=',$correo)->get()->pluck('contrasenia');
        if(isset($contraseniaConHash[0])){
            return $validez=Hash::check($contrasenia,$contraseniaConHash[0]);  
        }
        else{
            return false;
        }
          
        }
        catch(QueryException $ex){
            return false;
        }
                        

    }
}
