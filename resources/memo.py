from flask import request
from flask_jwt_extended import  get_jwt_identity, jwt_required
from flask_restful import Resource
from mysql.connector import Error
from mysql_connection import get_connection

class MemoListResource(Resource) :


    @jwt_required()
    def post(self) :


        
        data = request.get_json()
        print(data)

        user_id = get_jwt_identity()

        try :

            connection = get_connection()

            query = '''insert into memo
                            (userId,title,date,content)
                            values
                            (%s,%s,%s,%s);'''
            
            record = (user_id, 
                      data['title'],
                    data['date'],
                    data['content'])
            
            cursor = connection.cursor()
            cursor.execute(query,record)

            connection.commit()

            cursor.close()
            connection.close()

        except Error as e :
            print(e)
            cursor.close()
            connection.close()
            return {'error' : str(e)}, 500
        

        return {'result' : 'success'}, 200
    
    
    def get(self) :

        # 받아올 데이터 없음!
        

        try :
            connection = get_connection()
            query = '''select id, title, date, content
                        from memo;'''
            
            cursor = connection.cursor( dictionary= True)
            cursor.execute(query)
            result_list = cursor.fetchall()
            

            i = 0
            for row in result_list :
                result_list[i]['date'] = row['date'].isoformat()
                i = i + 1
            
            print(result_list)
            
            cursor.close()
            connection.close()


        except Error as e: 
            print(e)
            cursor.close()
            connection.close()
            return {'error' : str(e)} , 400

        return {'result' : 'success',
                'items' : result_list,
                'count' : len(result_list)},200
    
class MemoResource(Resource) :


    @jwt_required()
    def put(self, memo_id) :

        data = request.get_json()

        print(data)

        user_id = get_jwt_identity()

        try :

            connection = get_connection()
            query = '''update memo
                        set title =%s,
                        date = %s,
                        content = %s
                        where id = %s and userId = %s;'''
            
            record = ( data['title'],
                      data['date'],
                      data['content'],
                      memo_id, user_id)
            
            cursor = connection.cursor()
            cursor.execute(query,record)
            connection.commit()

            cursor.close()
            connection.close()
                                        

        except Error as e :
            print(e)
            cursor.close()
            connection()
            return {'error' : str(e)} , 400 
        


        return {'result' : 'success'}, 200
    

    @jwt_required()
    def delete(self,memo_id) :

        user_id = get_jwt_identity()

        try :
            connection = get_connection()
            query = '''delete from memo
                                where id = %s and userId = %s;'''
            
            record = (memo_id, user_id )

            cursor = connection.cursor()
            cursor.execute(query,record)
            connection.commit()

            cursor.close()
            connection.close()
        
        except Error as e :
            print(3)
            cursor.close()
            connection.close()
            return {'error' : str(e)} , 500
            

        return {'result' : 'success'}, 200
    


class MemoMyResource(Resource) :

    @jwt_required()

    def get(self) :

        user_id = get_jwt_identity()

        # 쿼리 스트링 또는 쿼리 파라미터를 통해서 데이터를 받아온다.
        offset = request.args.get('offset')
        limit = request.args.get('limit')

        try :
            connection = get_connection()
            query = '''select id, title, date,content
                            from memo
                            where userId = %s
                            order by date 
                            limit '''+str(offset) +''','''+str(limit)+''';'''
            record = (user_id, )
            cursor = connection.cursor(dictionary=True)
            cursor.execute(query,record)
            result_list = cursor.fetchall()

            i = 0
            for row in result_list :
                result_list[i]['date'] = row['date'].isoformat()
                i = i + 1

            print(user_id)
            print()
            print(result_list)
            print()

        except Error as e:

            print(e)
            cursor.close()
            connection.close()
            return {'error' : str(e)}, 500


        return {'result' : 'success',
                'items' : result_list,
                'count' : len(result_list)} , 200
    

class MemoFollowResource(Resource) :


    @jwt_required()
    def get(self) :

        offset = request.args.get('offset')
        limit = request.args.get('limit')
        user_id = get_jwt_identity()

        try :
            connection = get_connection()

            query = '''select m.id memoId , m.userId, m.title,
                                m.date, m.content, m.createdAt, m.updatedAt,
                                u.nickname
                                from follow f
                                join memo m
                                on f.followeeId = m.userId
                                join user u
                                on m.userId = u.id
                                where f.followerId = %s and m.date > now()
                                order by m.date desc
                                limit ''' +str(offset) +''','''+str(limit) +''' ;'''
            
            record = (user_id, )

            cursor = connection.cursor(dictionary= True)
            cursor.execute(query,record)

            resuli_list = cursor.fetchall()

            i = 0
            for row in resuli_list :
                resuli_list[i]['date'] = row['date'].isoformat()
                resuli_list[i]['createdAt']=row['createdAt'].isoformat()
                resuli_list[i]['updatedAt']=row['updatedAt'].isoformat()
                i = i + 1
                
        

            print()
            print(resuli_list)
            print()

            cursor.close()
            connection.close()
        
        except Error as e:
            print(e)
            cursor.close()
            connection.close()
            return {'error' : str(e)}, 400

        
        return {'result' : 'success',
                'items' : resuli_list,
                'count' : len(resuli_list)}, 200
    