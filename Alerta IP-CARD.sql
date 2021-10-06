with
    q1 as (
        select 
            ip,
            countrycode,
            merchant,
            sum(cnt) as cnt_30d

        from (
            select 
                cast(created as date) date,
                req_user_ip ip,
                countrycode,
                merchant,
                count(caseid) cnt

            from (
                select
                    *,
                    row_number() over (partition by caseid) as row_number

                from communication_logs.sherlock_analysis

                where cast(created as date) between current_date - interval '32' day and current_date - interval '1' day
                    and req_operation_type in ('WITH_CVV','WITHOUT_CVV','TOKEN')
                    and res_result = 'ACCEPT'
                )
            where row_number = 1 
                and req_user_ip is not null

            group by cast(created as date),req_user_ip ,countrycode, merchant
                
            order by count(caseid) desc
            )
        group by ip, countrycode, merchant
        ),
        
    q2 as (
        select
            req_user_ip as ip,
            countrycode,
            merchant,
            count(caseid) as cnt_1d
            
        from (
            select 
                *,
                row_number() over (partition by caseid) as row_number
                
            from communication_logs.sherlock_analysis
                
            where (cast(created AS date) = current_date 
                or (cast(created AS date) = current_date - interval '1' day and cast(hour as bigint) > extract(hour from current_time)))
               and req_operation_type in ('WITH_CVV','WITHOUT_CVV','TOKEN')
               and res_result = 'ACCEPT'
            )
        where row_number = 1
            and req_user_ip is not null
            
        group by 1,2,3
            
        order by count(caseid) desc
        ),
        
    q3 as (
        select
            countrycode,
            merchant,
            sum(cnt) as total_30d,
            count(distinct date) qty_dist_days
        
        from (
            select 
                cast(created as date) as date,
                countrycode,
                merchant,
                count(caseid) as cnt
            
            from communication_logs.sherlock_analysis
            
            where cast(created AS date) between current_date - interval '32' day and current_date - interval '1' day
                and req_operation_type in ('WITH_CVV','WITHOUT_CVV','TOKEN')
                and res_result = 'ACCEPT'
               
               group by cast(created as date), countrycode, merchant
               
               order by count(caseid) desc
               )
           group by countrycode, merchant
           ),

    q4 as (
        select
            countrycode,
            merchant,
            sum(cnt) as total_1d,
            count(distinct date) qty_dist_days
        
        from (
            select 
                cast(created as date) as date,
                countrycode,
                merchant,
                count(caseid) as cnt
            
            from communication_logs.sherlock_analysis
            
            where (cast(created AS date) = current_date 
                or (cast(created AS date) = current_date - interval '1' day and cast(hour as bigint) > extract(hour from current_time)))
               and req_operation_type in ('WITH_CVV','WITHOUT_CVV','TOKEN')
               and res_result = 'ACCEPT'
               
               group by cast(created as date), countrycode, merchant
               
               order by count(caseid) desc
               )
           group by countrycode, merchant
           )

select 
    variation.*

from (
    select
        uuid() as alert_id,
        'IP_VARIATION' as alert_name,
        'ANOMALY' as alert_type,
        q2.merchant, 
        merch.merchant_name,
        merch.industry,
        'CARD' as payment_method,
        q2.countrycode as country_code,
        cast(CURRENT_TIMESTAMP as timestamp) as alert_date,
        'IP' as anomaly_field,
        q2.ip as anomaly_field_value,
        'QUANTITY' as type,
        case
            when q1.cnt_30d = 0 then 50
            when q2.cnt_1d/q4.total_1d > 5*q1.cnt_30d/q3.total_30d then 5*q1.cnt_30d/q3.total_30d
            else null
        end as type_limit,
        q2.cnt_1d as type_value
    
    from q1

    join q2
        on q1.ip = q2.ip 
        and q1.countrycode = q2.countrycode 
        and q1.merchant = q2.merchant

    left join default.merchant_data_pf as merch
        on q1.merchant = merch.merchant_reference 
        and q1.countrycode = merch.country_code

    join q3
        on q1.merchant = q3.merchant 
        and q1.countrycode = q3.countrycode
    
    join q4
        on q1.merchant = q4.merchant 
        and q1.countrycode = q4.countrycode

    where q2.cnt_1d > 50
       and (q1.cnt_30d > 0 and q2.cnt_1d/q4.total_1d > 5*q1.cnt_30d/q3.total_30d)
       or (q1.cnt_30d = 0)
    
    ) variation

left join (
            select 
                row_number () over (partition by payment_method, country_code, merchant order by alert_date desc) as row_number, 
                *
           
            from fraud_alert.alert
            
           where alert_name = 'IP_VARIATION'
           ) ip_var
    on variation.payment_method = ip_var.payment_method
    and variation.country_code = ip_var.country_code
    and variation.merchant = ip_var.merchant
    
where (ip_var.payment_method is null
    and ip_var.country_code is null
    and ip_var.merchant is null) 
    or (ip_var.row_number = 1 
    and cast(ip_var.alert_date as date) <= current_date - interval '7' day)
;